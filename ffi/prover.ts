import { version } from "../package.json";
import { Logger } from "tslog";
import { spawn } from "child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "fs";
import { Argument, Command } from "commander";
import IPC from "node-ipc";
import {
  GasStation,
  ProtocolDetailsV1,
  ProtocolV1Versions,
} from "@arianee/common-types";
import { Core } from "@arianee/core";
import { ProtocolClientV1 } from "@arianee/arianee-protocol-client";
import { Prover } from "@arianee/privacy-circuits";
import {
  Wallet,
  ZeroAddress,
  BytesLike,
  ParamType,
  zeroPadValue,
  hashMessage,
} from "ethers";
import { stdoutWriteExit as _stdoutWriteExit } from "./helpers/stdout";
import { decodeArgs } from "./helpers/abi";

// Utilities
const stdoutWriteExit = (
  types: ReadonlyArray<string | ParamType>,
  values: ReadonlyArray<any>,
  exitCode = 0
) => {
  const { stdoutWrite } = program.opts();
  if (stdoutWrite) _stdoutWriteExit(types, values, exitCode);
};
const shutdown = () => {
  if (IPC.server) IPC.server.stop();
  process.exit(0);
};
process.on("SIGTERM", shutdown);

// Constants
const PROVER_IPC_SERVER_ID = "prover";
const PROVER_PID_FILE = "./prover.pid";

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
  .option("-ll, --log-level <level>", "logging level", "2")
  .option("-nsw, --no-stdout-write", "do not write command result to stdout")
  .on("option:log-level", (level) => {
    logger.settings.minLevel = level;
  });

program
  .command("exec")
  .description("Ask the prover server to execute a command")
  .addArgument(new Argument("<command>", "command to execute"))
  .addArgument(new Argument("<args>", "abi encoded arguments"))
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
  .addArgument(new Argument("<args>", "abi encoded arguments"))
  .action(async (args) => {
    if (!existsSync(PROVER_PID_FILE)) writeFileSync(PROVER_PID_FILE, "0");

    const pid = parseInt(readFileSync(PROVER_PID_FILE).toString());
    if (pid !== 0) {
      logger.warn("Prover already running");
      stdoutWriteExit(["bool"], [true]); // Exit without error
    }

    const childProcess = spawn("npm", ["run", "prover", "start", args], {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    childProcess.stdout.on("data", (data) => {
      if (data.toString().includes("Server started")) {
        logger.info("Server started");
        writeFileSync(PROVER_PID_FILE, childProcess.pid!.toString());
        childProcess.unref();
        stdoutWriteExit(["bool"], [true]);
      }
    });
    childProcess.on("error", (err) => {
      logger.error(err);
      stdoutWriteExit(["bool"], [false], 1);
    });
  });

program
  .command("start")
  .description("Start the prover server")
  .addArgument(new Argument("<args>", "abi encoded arguments"))
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
    const wallet = new Wallet(signerPkBytes);

    const protocolDetails: ProtocolDetailsV1 = {
      protocolVersion: String(decodedProgramArgs[1]) as ProtocolV1Versions,
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
      httpProvider: "",
      gasStation: "",
      soulbound: false,
    };

    const protocolV1 = new ProtocolClientV1(
      wallet as any,
      protocolDetails,
      {} as unknown as GasStation
    );

    logger.info("Initializing prover...");
    const prover = new Prover({
      core: Core.fromWallet(wallet),
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
      return;
    }

    let stopped = false;
    try {
      const pid = parseInt(readFileSync(PROVER_PID_FILE).toString());
      process.kill(-pid, "SIGTERM");
      logger.info("Server stopped");
      stopped = true;
    } catch {
      logger.error("Server could not be stopped");
    } finally {
      rmSync(PROVER_PID_FILE);
      stdoutWriteExit(["bool"], [stopped], stopped ? 0 : 1);
    }
  });

program.parse();

// Prover handlers
const handlers = {
  issuerProxy_computeCommitmentHash,
  issuerProxy_computeIntentHash,
  issuerProxy_generateProof,
  issuerProxy_computeCommitmentHashV2,
};

async function issuerProxy_computeCommitmentHash(
  prover: Prover,
  protocolV1: ProtocolClientV1,
  args: BytesLike
) {
  const decodedArgs = decodeArgs(["uint256"], args);
  const { commitmentHashAsHex } =
    await prover.issuerProxy.computeCommitmentHash({
      protocolV1,
      tokenId: decodedArgs[0],
    });
  return { types: ["uint256"], values: [commitmentHashAsHex] };
}

async function issuerProxy_computeIntentHash(
  prover: Prover,
  protocolV1: ProtocolClientV1,
  args: BytesLike
) {
  const decodedArgs = decodeArgs(["string", "string[]", "bytes", "bool"], args);
  const { intentHashAsStr } = await prover.issuerProxy.computeIntentHash({
    protocolV1,
    fragment: decodedArgs[0],
    values: decodeArgs(decodedArgs[1], decodedArgs[2]),
    needsCreditNoteProof: decodedArgs[3],
  });
  return { types: ["string"], values: [intentHashAsStr] };
}

async function issuerProxy_generateProof(
  prover: Prover,
  protocolV1: ProtocolClientV1,
  args: BytesLike
) {
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

// CommitmentHashV2

async function issuerProxy_computeCommitmentHashV2(
  prover: Prover,
  protocolV1: ProtocolClientV1,
  args: BytesLike
) {
  const decodedArgs = decodeArgs(["uint256"], args);
  const tokenId = decodedArgs[0];

  // INFO: This is a dummy implementation, we're waiting for DFNS to release the new APIs
  const chainId = protocolV1.protocolDetails.chainId;
  const smartAssetContractAddress =
    await protocolV1.smartAssetContract.getAddress();
  const message = `${chainId}.${smartAssetContractAddress}.${tokenId}.v2`; // We add `v2` to generate a different hash
  const digest = hashMessage(message);

  const { signature } = await prover.core.signDigest!(digest);
  const { r, s, v } = signature;

  // We use the internal method of the `Prover` class to compute the commitment hash, prevent re-write everything here
  const { commitmentHashAsHex } = (
    prover.issuerProxy as any
  )._computeCommitmentHash({ r, s, v });

  return { types: ["uint256"], values: [commitmentHashAsHex] };
}
