import { deleteOwnedHarnessSessionFile } from "./harness-path.mjs";

const filePath = process.argv[2];
if (!filePath) {
  throw new Error("session file path is required");
}

deleteOwnedHarnessSessionFile(filePath);
