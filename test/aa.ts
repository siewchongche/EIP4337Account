import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { deepHexlify } from "../../bundler/packages/utils"
import { calcPreVerificationGas } from "../../bundler/packages/sdk/src/calcPreVerificationGas"
import { BlsSignerFactory } from "@thehubbleproject/bls/dist/signer"

const entryPointAddr = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

const { HashZero, AddressZero } = ethers.constants
const { arrayify, hexlify, hexConcat, keccak256, parseEther, formatEther, defaultAbiCoder } = ethers.utils

describe("Account Abstraction", function () {

  async function deployFixture() {
    const [owner, bundler, paymasterSigner] = await ethers.getSigners()
    const provider = owner.provider!
    // const entryPoint = await ethers.getContractAt("EntryPoint", entryPointAddr)
    const entryPoint = await (await ethers.getContractFactory("EntryPoint")).deploy()
    const randomWallet = ethers.Wallet.createRandom().connect(provider)

    async function createEmptyUserOp(accountAddr: string, accountContractName: string) {
      const account = await ethers.getContractAt(accountContractName, accountAddr)
      const feeData = await provider.getFeeData()
      const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas!.toNumber()
      const nonce = await provider.getCode(accountAddr) == "0x" ?
        0 : (await account.callStatic.getNonce()).toNumber()
      return {
        sender: accountAddr,
        nonce,
        initCode: "0x",
        callData: "0x",
        callGasLimit: 0,
        verificationGasLimit: 5e6,
        preVerificationGas: 0,
        maxFeePerGas: feeData.lastBaseFeePerGas!.toNumber() + maxPriorityFeePerGas,
        maxPriorityFeePerGas,
        paymasterAndData: "0x",
        signature: await owner.signMessage("0x")
      }
    }
    
    async function estimateUserOpGas(userOp: any) {
      // userOp.preVerificationGas = calcPreVerificationGas(userOp)
      const err = await entryPoint.callStatic.simulateValidation(userOp).catch(e => e)
      if (!err.errorName.startsWith("ValidationResult")) {
        console.error("Error on simulateValidation:", err.errorArgs.reason)
        process.exit(1)
      }
      userOp.verificationGasLimit = err.errorArgs.returnInfo.preOpGas.toNumber()
      userOp.callGasLimit = (await provider.estimateGas({
        from: entryPoint.address, to: userOp.sender, data: userOp.callData
      })).toNumber()
      userOp.preVerificationGas = calcPreVerificationGas(userOp)
    }
    
    async function signUserOp(userOp: any) {
      const userOpHash = await entryPoint.getUserOpHash(userOp)
      userOp.signature = await owner.signMessage(arrayify(userOpHash))
    }

    return { owner, bundler, paymasterSigner, randomWallet, provider, entryPoint, createEmptyUserOp, estimateUserOpGas, signUserOp }
  }


  async function simpleAccount () {
    const { owner, bundler, paymasterSigner, provider, randomWallet, entryPoint, createEmptyUserOp, estimateUserOpGas, signUserOp } = await loadFixture(deployFixture)

    const simpleAccountFactory = await (await ethers.getContractFactory("SimpleAccountFactory")).deploy(entryPoint.address)
    const verifyingPaymaster = await (await ethers.getContractFactory("VerifyingPaymaster")).deploy(entryPoint.address, paymasterSigner.address)
    await verifyingPaymaster.deposit({ value: parseEther("1") })

    const accountAddr = await simpleAccountFactory.getAddress(owner.address, 0)
    const account = await ethers.getContractAt("SimpleAccount", accountAddr)
    // console.log(accountAddr) // 0xeeB75f48e73e0921F972f12a36D3E6332d53520C
    await owner.sendTransaction({ to: accountAddr, value: parseEther("1")})

    // create account
    {
      const userOp = await createEmptyUserOp(accountAddr, "SimpleAccount")
      userOp.initCode = hexConcat([
        simpleAccountFactory.address,
        simpleAccountFactory.interface.encodeFunctionData(
          "createAccount",
          [owner.address, 0]
        )
      ])
      await estimateUserOpGas(userOp)
      await signUserOp(userOp)
      await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
      expect(await account.getNonce()).to.eq(1)
    }

    
    // transfer eth - sponsor by paymaster
    {
      const accountBal = await entryPoint.balanceOf(accountAddr)
      const userOp = await createEmptyUserOp(accountAddr, "SimpleAccount")
      userOp.callData = account.interface.encodeFunctionData("execute", [
        randomWallet.address, parseEther("0.1"), "0x"
      ])
      const encodedValid = defaultAbiCoder.encode(["uint48", "uint48"], [0, 0])
      userOp.paymasterAndData = hexConcat([verifyingPaymaster.address, encodedValid, await paymasterSigner.signMessage("0x")])
      await estimateUserOpGas(userOp)
      const hash = await verifyingPaymaster.getHash(userOp, 0, 0)
      userOp.paymasterAndData = hexConcat([verifyingPaymaster.address, encodedValid, await paymasterSigner.signMessage(arrayify(hash))])
      await signUserOp(userOp)
      await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
      expect(await randomWallet.getBalance()).to.eq(parseEther("0.1"))
      expect(await entryPoint.balanceOf(accountAddr)).to.eq(accountBal)
      expect(await entryPoint.balanceOf(verifyingPaymaster.address)).to.lt(parseEther("1"))
    }
  }


  async function gnosisSafeAccount() {
    const { owner, bundler, randomWallet, entryPoint, createEmptyUserOp, estimateUserOpGas, signUserOp } = await loadFixture(deployFixture)

    const proxyFactory = await (await ethers.getContractFactory("GnosisSafeProxyFactory")).deploy()
    const safeSingleton = await (await ethers.getContractFactory("GnosisSafe")).deploy()
    const manager = await (await ethers.getContractFactory("EIP4337Manager")).deploy(entryPointAddr)
    const accountFactory = await (await ethers.getContractFactory("GnosisSafeAccountFactory")).deploy(
      proxyFactory.address, safeSingleton.address, manager.address
    )
    await accountFactory.createAccount(owner.address, 0)
    const accountAddr = await accountFactory.getAddress(owner.address, 0)
    // expect(await provider.getCode(accountAddr)).not.eq("0x") // account successfully created
    const account = await ethers.getContractAt("GnosisSafeProxy", accountAddr)

    await owner.sendTransaction({ to: accountAddr, value: parseEther("1") })

    const userOp = await createEmptyUserOp(account.address, "EIP4337Fallback")
    userOp.callData = manager.interface.encodeFunctionData("executeAndRevert", [
      randomWallet.address, parseEther("0.1"), "0x", 0
    ])
    await estimateUserOpGas(userOp)
    await signUserOp(userOp)
    await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    expect(await randomWallet.getBalance()).to.eq(parseEther("0.1"))
  }


  async function blsAccount() {
    const { owner, provider, bundler, entryPoint, createEmptyUserOp, estimateUserOpGas, signUserOp } = await loadFixture(deployFixture)

    const blsOpen = await (await ethers.getContractFactory("BLSOpen")).deploy()
    const aggregator = await (await ethers.getContractFactory("BLSSignatureAggregator", {
      libraries: { BLSOpen: blsOpen.address }
    })).deploy()
    const factory = await (await ethers.getContractFactory("BLSAccountFactory")).deploy(entryPointAddr, aggregator.address)

    const blsSignerFactory = await BlsSignerFactory.new()
    const blsDomain = await aggregator.BLS_DOMAIN()

    const signer1 = ethers.Wallet.createRandom()
    const blsSigner1 = blsSignerFactory.getSigner(arrayify(blsDomain), signer1.privateKey)
    const account1Addr = await factory.getAddress(0, blsSigner1.pubkey)
    await owner.sendTransaction({ to: account1Addr, value: parseEther("1") })
    const userOp1 = await createEmptyUserOp(account1Addr, "BLSAccount")
    userOp1.initCode = hexConcat([
      factory.address,
      factory.interface.encodeFunctionData("createAccount", [0, blsSigner1.pubkey])
    ])
    await estimateUserOpGas(userOp1)
    const userOp1Hash = await aggregator.getUserOpHash(userOp1)
    userOp1.signature = ethers.utils.hexConcat(blsSigner1.sign(userOp1Hash))

    const signer2 = ethers.Wallet.createRandom()
    const blsSigner2 = blsSignerFactory.getSigner(arrayify(blsDomain), signer2.privateKey)
    const account2Addr = await factory.getAddress(0, blsSigner2.pubkey)
    await owner.sendTransaction({ to: account2Addr, value: parseEther("1") })
    const userOp2 = await createEmptyUserOp(account2Addr, "BLSAccount")
    userOp2.initCode = hexConcat([
      factory.address,
      factory.interface.encodeFunctionData("createAccount", [0, blsSigner2.pubkey])
    ])
    await estimateUserOpGas(userOp2)
    const userOp2Hash = await aggregator.getUserOpHash(userOp2)
    userOp2.signature = ethers.utils.hexConcat(blsSigner2.sign(userOp2Hash))

    await entryPoint.connect(bundler).handleAggregatedOps([{
      userOps: [userOp1, userOp2],
      aggregator: aggregator.address,
      signature: await aggregator.aggregateSignatures([userOp1, userOp2])
    }], bundler.address)
    expect(await provider.getCode(account1Addr)).not.eq("0x")
    expect(await provider.getCode(account2Addr)).not.eq("0x")
  }


  async function simpleAccountWithMultisig() {
    const { owner, provider, bundler, randomWallet, entryPoint, createEmptyUserOp, estimateUserOpGas, signUserOp } = await loadFixture(deployFixture)

    const owner2 = ethers.Wallet.createRandom().connect(provider)
    const owner3 = ethers.Wallet.createRandom().connect(provider)

    const simpleAccountWithMultiSigFactory = await (await ethers.getContractFactory("SimpleAccountWithMultiSigFactory")).deploy(entryPoint.address)
    await simpleAccountWithMultiSigFactory.createAccount([owner.address, owner2.address, owner3.address], 2, 0)
    const accountAddr = await simpleAccountWithMultiSigFactory.getAddress([owner.address, owner2.address, owner3.address], 2, 0)
    const account = await ethers.getContractAt("SimpleAccountWithMultiSig", accountAddr)
    await owner.sendTransaction({ to: accountAddr, value: parseEther("1")})

    const userOp = await createEmptyUserOp(accountAddr, "SimpleAccountWithMultiSig")
    userOp.callData = account.interface.encodeFunctionData("execute", [randomWallet.address, parseEther("0.1"), "0x"])
    // userOp.signature = "0x"
    let userOpHash = await entryPoint.getUserOpHash(userOp)
    const dummySigList = [await owner.signMessage(arrayify(userOpHash)), await owner2.signMessage(arrayify(userOpHash))]
    if (ethers.BigNumber.from(owner.address).gt(ethers.BigNumber.from(owner2.address))) dummySigList.reverse()
    userOp.signature = hexConcat(dummySigList)
    await estimateUserOpGas(userOp)

    userOpHash = await entryPoint.getUserOpHash(userOp)
    const sigList = [await owner2.signMessage(arrayify(userOpHash)), await owner3.signMessage(arrayify(userOpHash))]
    if (ethers.BigNumber.from(owner2.address).gt(ethers.BigNumber.from(owner3.address))) sigList.reverse()
    userOp.signature = hexConcat(sigList)

    await entryPoint.connect(bundler).handleOps([userOp], bundler.address)
    expect(await randomWallet.getBalance()).to.eq(parseEther("0.1"))
  }




  // it("Simple account", simpleAccount)
  // it("Gnosis safe account", gnosisSafeAccount)
  // it("BLS account", blsAccount)
  it("Simple account with multisig", simpleAccountWithMultisig)
})
