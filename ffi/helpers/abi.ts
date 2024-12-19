import { AbiCoder } from "ethers";
import { BytesLike } from "ethers";
import { ParamType } from "ethers";

export const decodeArgs = (
  types: ReadonlyArray<string | ParamType>,
  data: BytesLike
) => {
  return AbiCoder.defaultAbiCoder().decode(types, data);
};
