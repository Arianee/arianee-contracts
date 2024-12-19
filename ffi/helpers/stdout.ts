import { AbiCoder } from "ethers";
import { ParamType } from "ethers";

export const stdoutWriteExit = (
  types: ReadonlyArray<string | ParamType>,
  values: ReadonlyArray<any>,
  exitCode = 0
) => {
  process.stdout.write(AbiCoder.defaultAbiCoder().encode(types, values));
  process.exit(exitCode);
};
