module.exports = {
    extension: ["ts"],
    spec: "test/**/*.spec.ts",
    require: "ts-node/register",
    "node-option": [
        "experimental-specifier-resolution=node",
        "loader=ts-node/esm",
    ],
};
