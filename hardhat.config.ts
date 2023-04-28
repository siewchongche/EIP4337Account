import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.18",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    },
  },
  // networks: {
  //   hardhat: {
  //     forking: {
  //       url: "https://eth-mainnet.g.alchemy.com/v2/5cgc8F-s3YG8Z8iXpTw5fBLS1Z9-syW3",
  //       blockNumber: 17103100
  //     }
  //   }
  // },
};

export default config;
