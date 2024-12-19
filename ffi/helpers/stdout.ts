import { AbiCoder } from "ethers";
import { ParamType } from "ethers";

export const stdoutWrite = (
  types: ReadonlyArray<string | ParamType>,
  values: ReadonlyArray<any>
) => {
  process.stdout.write(AbiCoder.defaultAbiCoder().encode(types, values));
};
