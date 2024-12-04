import { createRequire } from "module";
import { Logger } from "tslog";
import { Command } from "commander";
import IPC from "node-ipc";
import { Core } from "@arianee/core";
import { Prover } from "@arianee/privacy-circuits";
import { AbiCoder, Wallet, ZeroAddress, zeroPadValue } from "ethers";
import { spawn } from "child_process";
import { lock } from "cross-process-lock";
import { existsSync, readFileSync, rmSync, writeFileSync } from "fs";
import { ProtocolClientV1 } from "@arianee/arianee-protocol-client";

const require = createRequire(import.meta.url);
const { version } = require("../package.json");

// Utilities
const stdoutWriteExit = (types, values, exitCode = 0) => {
  const { stdoutWrite } = program.opts();
  if (stdoutWrite) {
    process.stdout.write(AbiCoder.defaultAbiCoder().encode(types, values));
  }
  process.exit(exitCode);
};
const decodeArgs = (types, data) => {
  return AbiCoder.defaultAbiCoder().decode(types, data);
};
const shutdown = () => {
  if (IPC.server) IPC.server.stop();
  process.exit(0);
};
process.on("SIGTERM", shutdown);

// Constants
const PROVER_IPC_SERVER_ID = "prover";
const PROVER_PID_FILE = "./prover.pid";
const PROVER_PID_FILE_LOCK = `${PROVER_PID_FILE}.lock`;

// IPC Configuration
IPC.config.silent = true;
IPC.config.retry = 500;
IPC.config.maxRetries = 2;

// Program
const logger = new Logger();

const program = new Command();
program
  .name("prover")
  .description(
    "Prover from `@arianee/privacy-circuits` as a CLI to be used from Foundry Rust FFI"
  )
  .version(version)
  .option("-ll, --log-level <level>", "logging level", 2)
  .option("-nsw, --no-stdout-write", "do not write command result to stdout")
  .on("option:log-level", (level) => {
    logger.settings.minLevel = level;
  });

program
  .command("exec")
  .description("Ask the prover server to execute a command")
  .addArgument("<command>", "command to execute")
  .addArgument("<args>", "abi encoded arguments")
  .action(async (command, args) => {
    IPC.connectTo(PROVER_IPC_SERVER_ID, () => {
      IPC.of.prover.on("connect", () => {
        IPC.of.prover.emit("execute", { command, args });
      });
      IPC.of.prover.on("result", (data) => {
        const { types, values } = data;
        logger.debug(`Received result: (${types})[${values}]`);
        stdoutWriteExit(types, values);
      });
    });
  });

program
  .command("init")
  .description("Spawn a prover server in a detached process")
  .addArgument("<args>", "abi encoded arguments")
  .action(async (args) => {
    if (!existsSync(PROVER_PID_FILE)) writeFileSync(PROVER_PID_FILE, "0");

    const unlock = await lock(PROVER_PID_FILE);
    const pid = parseInt(readFileSync(PROVER_PID_FILE).toString());
    if (pid !== 0) {
      logger.warn("Prover already running");
      unlock();
      stdoutWriteExit(["bool"], [true]); // Exit without error
    }

    const childProcess = spawn("npm", ["run", "prover", "start", args], {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    childProcess.stdout.on("data", (data) => {
      if (data.toString().includes("Server started")) {
        logger.info("Server started");
        writeFileSync(PROVER_PID_FILE, childProcess.pid.toString());
        childProcess.unref();
        unlock();
        stdoutWriteExit(["bool"], [true]);
      }
    });
    childProcess.on("error", (err) => {
      logger.error(err);
      unlock();
      stdoutWriteExit(["bool"], [false], 1);
    });
  });

program
  .command("start")
  .description("Start the prover server")
  .addArgument("<args>", "abi encoded arguments")
  .action(async (programArgs) => {
    logger.debug(`PID: ${process.pid}`);
    const decodedProgramArgs = decodeArgs(
      [
        "uint256",
        "string",
        "uint256",
        "address",
        "address",
        "address",
        "address",
        "address",
        "address",
        "address",
        "address",
        "address",
        "address",
        "address",
      ],
      programArgs
    );
    if (decodedProgramArgs.length !== 14) {
      logger.error("Invalid arguments");
      process.exit(1);
    }

    const signerPk = decodedProgramArgs[0];
    const signerPkBytes = zeroPadValue(`0x${signerPk.toString(16)}`, 32);
    const signer = new Wallet(signerPkBytes);

    const protocolDetails = {
      protocolVersion: String(decodedProgramArgs[1]),
      chainId: Number(decodedProgramArgs[2]),
      contractAdresses: {
        aria: String(decodedProgramArgs[3]),
        creditHistory: String(decodedProgramArgs[4]),
        eventArianee: String(decodedProgramArgs[5]),
        identity: String(decodedProgramArgs[6]),
        smartAsset: String(decodedProgramArgs[7]),
        store: String(decodedProgramArgs[8]),
        lost: String(decodedProgramArgs[9]),
        whitelist: String(decodedProgramArgs[10]),
        message: String(decodedProgramArgs[11]),
        userAction: ZeroAddress,
        updateSmartAssets: String(decodedProgramArgs[12]),
        issuerProxy: String(decodedProgramArgs[13]),
        creditNotePool: ZeroAddress,
      },
    };

    const protocolV1 = new ProtocolClientV1(signer, protocolDetails);

    logger.info("Initializing prover...");
    const prover = new Prover({
      core: Core.fromWallet(signer),
      circuitsBuildPath: "node_modules/@arianee/privacy-circuits/build",
      useCreditNotePool: false,
    });
    await prover.init();
    logger.info("Prover initialized");

    logger.info("Starting server...");
    IPC.config.id = PROVER_IPC_SERVER_ID;
    IPC.serve(() => {
      IPC.server.on("execute", async (data, socket) => {
        const { command, args } = data;
        let result = { types: ["bool"], values: [false] };
        try {
          result = await handlers[command](prover, protocolV1, args);
        } catch (err) {
          logger.error(err);
        }
        IPC.server.emit(socket, "result", result);
      });
    });
    IPC.server.start();
    logger.info(
      `Server started on ${IPC.config.socketRoot}${IPC.config.appspace}${IPC.config.id}`
    );
  });

program
  .command("stop")
  .description("Stop the prover server")
  .action(async () => {
    if (!existsSync(PROVER_PID_FILE)) {
      logger.warn("Server not running");
      if (existsSync(PROVER_PID_FILE_LOCK)) rmSync(PROVER_PID_FILE_LOCK);
      return;
    }

    try {
      const pid = parseInt(readFileSync(PROVER_PID_FILE).toString());
      process.kill(-pid, "SIGTERM");
      logger.info("Server stopped");
    } catch {
      logger.error("Server could not be stopped");
    } finally {
      rmSync(PROVER_PID_FILE);
      rmSync(PROVER_PID_FILE_LOCK);
    }
  });

program.parse();

// Prover handlers
const handlers = {
  issuerProxy_computeCommitmentHash,
  issuerProxy_computeIntentHash,
  issuerProxy_generateProof,
};

async function issuerProxy_computeCommitmentHash(prover, protocolV1, args) {
  const decodedArgs = decodeArgs(["uint256"], args);
  const { commitmentHashAsHex } =
    await prover.issuerProxy.computeCommitmentHash({
      protocolV1,
      tokenId: parseInt(decodedArgs[0]),
    });
  return { types: ["uint256"], values: [commitmentHashAsHex] };
}
async function issuerProxy_computeIntentHash(prover, protocolV1, args) {
  const decodedArgs = decodeArgs(["string", "bytes", "bool"], args);
  const { intentHashAsStr } = await prover.issuerProxy.computeIntentHash({
    protocolV1,
    fragment: decodedArgs[0],
    values: decodeArgs(
      [
        "address",
        "uint256",
        "uint256",
        "bytes32",
        "string",
        "address",
        "uint256",
        "bool",
        "address",
      ],
      decodedArgs[1]
    ),
    needsCreditNoteProof: decodedArgs[2],
  });
  return { types: ["string"], values: [intentHashAsStr] };
}

async function issuerProxy_generateProof(prover, protocolV1, args) {
  const decodedArgs = decodeArgs(["uint256", "string"], args);
  const { callData } = await prover.issuerProxy.generateProof({
    protocolV1,
    tokenId: decodedArgs[0],
    intentHashAsStr: decodedArgs[1],
  });
  return {
    types: ["tuple(uint256[2], uint256[2][2], uint256[2], uint256[3])"],
    values: [callData],
  };
}
