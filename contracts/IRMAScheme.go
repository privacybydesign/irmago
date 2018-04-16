// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contracts

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// IRMASchemeABI is the input ABI used to generate the binding from.
const IRMASchemeABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"_issuerId\",\"type\":\"string\"},{\"name\":\"_credId\",\"type\":\"string\"}],\"name\":\"getIssuerCredentialById\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_issuerId\",\"type\":\"string\"},{\"name\":\"_credentialId\",\"type\":\"string\"},{\"name\":\"_logoUrl\",\"type\":\"string\"},{\"name\":\"_issueSpec\",\"type\":\"bytes\"}],\"name\":\"addIssuerCredential\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_issuerId\",\"type\":\"string\"},{\"name\":\"_key\",\"type\":\"bytes\"}],\"name\":\"addIssuerPublicKey\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"metadata\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"issuerIds\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getNumberOfIssuers\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_id\",\"type\":\"string\"},{\"name\":\"_logoUrl\",\"type\":\"string\"},{\"name\":\"_metadata\",\"type\":\"bytes\"}],\"name\":\"addIssuer\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_issuerId\",\"type\":\"string\"},{\"name\":\"_credIndex\",\"type\":\"uint256\"}],\"name\":\"getIssuerCredentialIdByCredentialIndex\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"id\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_id\",\"type\":\"string\"}],\"name\":\"getIssuerById\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"bytes\"},{\"name\":\"\",\"type\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_issuerId\",\"type\":\"string\"},{\"name\":\"_keyIndex\",\"type\":\"uint256\"}],\"name\":\"getIssuerPublicKeyById\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"},{\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"_id\",\"type\":\"string\"},{\"name\":\"_metadata\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

// IRMASchemeBin is the compiled bytecode used for deploying new contracts.
const IRMASchemeBin = `0x606060405234156200001057600080fd5b60405162001d3f38038062001d3f8339810160405280805182019190602001805160018054600160a060020a03191633600160a060020a031617905591909101905060008280516200006792916020019062000086565b5060028180516200007d92916020019062000086565b5050506200012b565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f10620000c957805160ff1916838001178555620000f9565b82800160010185558215620000f9579182015b82811115620000f9578251825591602001919060010190620000dc565b50620001079291506200010b565b5090565b6200012891905b8082111562000107576000815560010162000112565b90565b611c04806200013b6000396000f3006060604052600436106100b95763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166313246ba281146100be57806316f3b1a51461029b57806335ec27c4146103c6578063392f37e914610459578063468e9703146104e357806369c05a99146104f95780636cd4b82e1461051e5780638da5cb5b146105f3578063a23b430214610622578063af640d0f14610675578063b534697014610688578063c2c980771461084a575b600080fd5b34156100c957600080fd5b61015160046024813581810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f01602080910402602001604051908101604052818152929190602084018383808284375094965061091b95505050505050565b60405180806020018060200180602001848103845287818151815260200191508051906020019080838360005b8381101561019657808201518382015260200161017e565b50505050905090810190601f1680156101c35780820380516001836020036101000a031916815260200191505b50848103835286818151815260200191508051906020019080838360005b838110156101f95780820151838201526020016101e1565b50505050905090810190601f1680156102265780820380516001836020036101000a031916815260200191505b50848103825285818151815260200191508051906020019080838360005b8381101561025c578082015183820152602001610244565b50505050905090810190601f1680156102895780820380516001836020036101000a031916815260200191505b50965050505050505060405180910390f35b34156102a657600080fd5b6103b260046024813581810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f01602080910402602001604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f01602080910402602001604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f016020809104026020016040519081016040528181529291906020840183838082843750949650610c1995505050505050565b604051901515815260200160405180910390f35b34156103d157600080fd5b6103b260046024813581810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f016020809104026020016040519081016040528181529291906020840183838082843750949650610de895505050505050565b341561046457600080fd5b61046c610eea565b60405160208082528190810183818151815260200191508051906020019080838360005b838110156104a8578082015183820152602001610490565b50505050905090810190601f1680156104d55780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34156104ee57600080fd5b61046c600435610f88565b341561050457600080fd5b61050c611010565b60405190815260200160405180910390f35b341561052957600080fd5b6103b260046024813581810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f01602080910402602001604051908101604052818152929190602084018383808284378201915050505050509190803590602001908201803590602001908080601f01602080910402602001604051908101604052818152929190602084018383808284375094965061101795505050505050565b34156105fe57600080fd5b610606611283565b604051600160a060020a03909116815260200160405180910390f35b341561062d57600080fd5b61015160046024813581810190830135806020601f82018190048102016040519081016040528181529291906020840183838082843750949650509335935061129292505050565b341561068057600080fd5b61046c6115cb565b341561069357600080fd5b6106d960046024813581810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284375094965061163695505050505050565b60405180806020018060200187600160a060020a0316600160a060020a031681526020018060200186815260200185815260200184810384528a818151815260200191508051906020019080838360005b8381101561074257808201518382015260200161072a565b50505050905090810190601f16801561076f5780820380516001836020036101000a031916815260200191505b50848103835289818151815260200191508051906020019080838360005b838110156107a557808201518382015260200161078d565b50505050905090810190601f1680156107d25780820380516001836020036101000a031916815260200191505b50848103825287818151815260200191508051906020019080838360005b838110156108085780820151838201526020016107f0565b50505050905090810190601f1680156108355780820380516001836020036101000a031916815260200191505b50995050505050505050505060405180910390f35b341561085557600080fd5b61089d60046024813581810190830135806020601f8201819004810201604051908101604052818152929190602084018383808284375094965050933593506118e492505050565b60405182815260406020820181815290820183818151815260200191508051906020019080838360005b838110156108df5780820151838201526020016108c7565b50505050905090810190601f16801561090c5780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b610923611a43565b61092b611a43565b610933611a43565b6000806003876040518082805190602001908083835b602083106109685780518252601f199092019160209182019101610949565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490925060ff1615156109af57600080fd5b81600701866040518082805190602001908083835b602083106109e35780518252601f1990920191602091820191016109c4565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490915060ff161515610a2a57600080fd5b806001018160020182600301828054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610acb5780601f10610aa057610100808354040283529160200191610acb565b820191906000526020600020905b815481529060010190602001808311610aae57829003601f168201915b50505050509250818054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610b675780601f10610b3c57610100808354040283529160200191610b67565b820191906000526020600020905b815481529060010190602001808311610b4a57829003601f168201915b50505050509150808054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610c035780601f10610bd857610100808354040283529160200191610c03565b820191906000526020600020905b815481529060010190602001808311610be657829003601f168201915b5050505050905094509450945050509250925092565b6000806003866040518082805190602001908083835b60208310610c4e5780518252601f199092019160209182019101610c2f565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490915060ff161515610c995760009150610ddf565b600381015433600160a060020a03908116911614610cba5760009150610ddf565b6080604051908101604052806001151581526020018681526020018581526020018481525081600701866040518082805190602001908083835b60208310610d135780518252601f199092019160209182019101610cf4565b6001836020036101000a0380198251168184511680821785525050505050509050019150509081526020016040519081900390208151815460ff1916901515178155602082015181600101908051610d6f929160200190611a55565b50604082015181600201908051610d8a929160200190611a55565b50606082015181600301908051610da5929160200190611a55565b50505060088101805460018101610dbc8382611ad3565b6000928352602090922001868051610dd8929160200190611a55565b5050600191505b50949350505050565b6000806003846040518082805190602001908083835b60208310610e1d5780518252601f199092019160209182019101610dfe565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490915060ff161515610e685760009150610ee3565b600381015433600160a060020a03908116911614610e895760009150610ee3565b6040805190810160409081526006830154808352602080840187905260009182526005850190522081518155602082015181600101908051610ecf929160200190611a55565b505050600681018054600190810190915591505b5092915050565b60028054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610f805780601f10610f5557610100808354040283529160200191610f80565b820191906000526020600020905b815481529060010190602001808311610f6357829003601f168201915b505050505081565b6004805482908110610f9657fe5b90600052602060002090016000915090508054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610f805780601f10610f5557610100808354040283529160200191610f80565b6004545b90565b6000835115156110295750600061127c565b6003846040518082805190602001908083835b6020831061105b5780518252601f19909201916020918201910161103c565b6001836020036101000a0380198251168184511680821785525050505050509050019150509081526020016040519081900390205460ff16156110a05750600061127c565b60e06040519081016040528060011515815260200185815260200184815260200133600160a060020a031681526020018381526020016000815260200160006040518059106110ec5750595b90808252806020026020018201604052801561112257816020015b61110f611a43565b8152602001906001900390816111075790505b5090526003856040518082805190602001908083835b602083106111575780518252601f199092019160209182019101611138565b6001836020036101000a0380198251168184511680821785525050505050509050019150509081526020016040519081900390208151815460ff19169015151781556020820151816001019080516111b3929160200190611a55565b506040820151816002019080516111ce929160200190611a55565b50606082015160038201805473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a039290921691909117905560808201518160040190805161121d929160200190611a55565b5060a0820151816006015560c082015181600801908051611242929160200190611afc565b505060048054909150600181016112598382611ad3565b6000928352602090922001858051611275929160200190611a55565b5050600190505b9392505050565b600154600160a060020a031681565b61129a611a43565b6112a2611a43565b6112aa611a43565b60008060006003886040518082805190602001908083835b602083106112e15780518252601f1990920191602091820191016112c2565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490935060ff16151561132857600080fd5b6008830154871061133857600080fd5b6008830180548890811061134857fe5b90600052602060002090019150826007018260405180828054600181600116156101000203166002900480156113b55780601f106113935761010080835404028352918201916113b5565b820191906000526020600020905b8154815290600101906020018083116113a1575b50509283525050602001604051908190039020805490915060ff1615156113db57600080fd5b806001018160020182600301828054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561147c5780601f106114515761010080835404028352916020019161147c565b820191906000526020600020905b81548152906001019060200180831161145f57829003601f168201915b50505050509250818054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156115185780601f106114ed57610100808354040283529160200191611518565b820191906000526020600020905b8154815290600101906020018083116114fb57829003601f168201915b50505050509150808054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156115b45780601f10611589576101008083540402835291602001916115b4565b820191906000526020600020905b81548152906001019060200180831161159757829003601f168201915b505050505090509550955095505050509250925092565b60008054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610f805780601f10610f5557610100808354040283529160200191610f80565b61163e611a43565b611646611a43565b6000611650611a43565b60008060006003886040518082805190602001908083835b602083106116875780518252601f199092019160209182019101611668565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490915060ff16156118da5780600101816002018260030160009054906101000a9004600160a060020a03168360040184600601548560080180549050858054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561178e5780601f106117635761010080835404028352916020019161178e565b820191906000526020600020905b81548152906001019060200180831161177157829003601f168201915b50505050509550848054600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280546001816001161561010002031660029004801561182a5780601f106117ff5761010080835404028352916020019161182a565b820191906000526020600020905b81548152906001019060200180831161180d57829003601f168201915b50505050509450828054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156118c65780601f1061189b576101008083540402835291602001916118c6565b820191906000526020600020905b8154815290600101906020018083116118a957829003601f168201915b505050505092509650965096509650965096505b5091939550919395565b60006118ee611a43565b6000806003866040518082805190602001908083835b602083106119235780518252601f199092019160209182019101611904565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051908190039020805490925060ff16151561196a57600080fd5b6006820154851061197a57600080fd5b8160050160008681526020019081526020016000209050806000015481600101808054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015611a2f5780601f10611a0457610100808354040283529160200191611a2f565b820191906000526020600020905b815481529060010190602001808311611a1257829003601f168201915b505050505090509350935050509250929050565b60206040519081016040526000815290565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f10611a9657805160ff1916838001178555611ac3565b82800160010185558215611ac3579182015b82811115611ac3578251825591602001919060010190611aa8565b50611acf929150611b54565b5090565b815481835581811511611af757600083815260209020611af7918101908301611b6e565b505050565b828054828255906000526020600020908101928215611b48579160200282015b82811115611b4857825182908051611b38929160200190611a55565b5091602001919060010190611b1c565b50611acf929150611b6e565b61101491905b80821115611acf5760008155600101611b5a565b61101491905b80821115611acf576000611b888282611b91565b50600101611b74565b50805460018160011615610100020316600290046000825580601f10611bb75750611bd5565b601f016020900490600052602060002090810190611bd59190611b54565b505600a165627a7a72305820990cbe9cf23ea6d199dd7882feefe2acd072961b666225831654359ea9bee3560029`

// DeployIRMAScheme deploys a new Ethereum contract, binding an instance of IRMAScheme to it.
func DeployIRMAScheme(auth *bind.TransactOpts, backend bind.ContractBackend, _id string, _metadata []byte) (common.Address, *types.Transaction, *IRMAScheme, error) {
	parsed, err := abi.JSON(strings.NewReader(IRMASchemeABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(IRMASchemeBin), backend, _id, _metadata)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &IRMAScheme{IRMASchemeCaller: IRMASchemeCaller{contract: contract}, IRMASchemeTransactor: IRMASchemeTransactor{contract: contract}}, nil
}

// IRMAScheme is an auto generated Go binding around an Ethereum contract.
type IRMAScheme struct {
	IRMASchemeCaller     // Read-only binding to the contract
	IRMASchemeTransactor // Write-only binding to the contract
}

// IRMASchemeCaller is an auto generated read-only Go binding around an Ethereum contract.
type IRMASchemeCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IRMASchemeTransactor is an auto generated write-only Go binding around an Ethereum contract.
type IRMASchemeTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// IRMASchemeSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type IRMASchemeSession struct {
	Contract     *IRMAScheme       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// IRMASchemeCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type IRMASchemeCallerSession struct {
	Contract *IRMASchemeCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// IRMASchemeTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type IRMASchemeTransactorSession struct {
	Contract     *IRMASchemeTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// IRMASchemeRaw is an auto generated low-level Go binding around an Ethereum contract.
type IRMASchemeRaw struct {
	Contract *IRMAScheme // Generic contract binding to access the raw methods on
}

// IRMASchemeCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type IRMASchemeCallerRaw struct {
	Contract *IRMASchemeCaller // Generic read-only contract binding to access the raw methods on
}

// IRMASchemeTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type IRMASchemeTransactorRaw struct {
	Contract *IRMASchemeTransactor // Generic write-only contract binding to access the raw methods on
}

// NewIRMAScheme creates a new instance of IRMAScheme, bound to a specific deployed contract.
func NewIRMAScheme(address common.Address, backend bind.ContractBackend) (*IRMAScheme, error) {
	contract, err := bindIRMAScheme(address, backend, backend)
	if err != nil {
		return nil, err
	}
	return &IRMAScheme{IRMASchemeCaller: IRMASchemeCaller{contract: contract}, IRMASchemeTransactor: IRMASchemeTransactor{contract: contract}}, nil
}

// NewIRMASchemeCaller creates a new read-only instance of IRMAScheme, bound to a specific deployed contract.
func NewIRMASchemeCaller(address common.Address, caller bind.ContractCaller) (*IRMASchemeCaller, error) {
	contract, err := bindIRMAScheme(address, caller, nil)
	if err != nil {
		return nil, err
	}
	return &IRMASchemeCaller{contract: contract}, nil
}

// NewIRMASchemeTransactor creates a new write-only instance of IRMAScheme, bound to a specific deployed contract.
func NewIRMASchemeTransactor(address common.Address, transactor bind.ContractTransactor) (*IRMASchemeTransactor, error) {
	contract, err := bindIRMAScheme(address, nil, transactor)
	if err != nil {
		return nil, err
	}
	return &IRMASchemeTransactor{contract: contract}, nil
}

// bindIRMAScheme binds a generic wrapper to an already deployed contract.
func bindIRMAScheme(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(IRMASchemeABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IRMAScheme *IRMASchemeRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _IRMAScheme.Contract.IRMASchemeCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IRMAScheme *IRMASchemeRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IRMAScheme.Contract.IRMASchemeTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IRMAScheme *IRMASchemeRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IRMAScheme.Contract.IRMASchemeTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_IRMAScheme *IRMASchemeCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _IRMAScheme.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_IRMAScheme *IRMASchemeTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _IRMAScheme.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_IRMAScheme *IRMASchemeTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _IRMAScheme.Contract.contract.Transact(opts, method, params...)
}

// GetIssuerById is a free data retrieval call binding the contract method 0xb5346970.
//
// Solidity: function getIssuerById(_id string) constant returns(string, string, address, bytes, uint256, uint256)
func (_IRMAScheme *IRMASchemeCaller) GetIssuerById(opts *bind.CallOpts, _id string) (string, string, common.Address, []byte, *big.Int, *big.Int, error) {
	var (
		ret0 = new(string)
		ret1 = new(string)
		ret2 = new(common.Address)
		ret3 = new([]byte)
		ret4 = new(*big.Int)
		ret5 = new(*big.Int)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
		ret3,
		ret4,
		ret5,
	}
	err := _IRMAScheme.contract.Call(opts, out, "getIssuerById", _id)
	return *ret0, *ret1, *ret2, *ret3, *ret4, *ret5, err
}

// GetIssuerById is a free data retrieval call binding the contract method 0xb5346970.
//
// Solidity: function getIssuerById(_id string) constant returns(string, string, address, bytes, uint256, uint256)
func (_IRMAScheme *IRMASchemeSession) GetIssuerById(_id string) (string, string, common.Address, []byte, *big.Int, *big.Int, error) {
	return _IRMAScheme.Contract.GetIssuerById(&_IRMAScheme.CallOpts, _id)
}

// GetIssuerById is a free data retrieval call binding the contract method 0xb5346970.
//
// Solidity: function getIssuerById(_id string) constant returns(string, string, address, bytes, uint256, uint256)
func (_IRMAScheme *IRMASchemeCallerSession) GetIssuerById(_id string) (string, string, common.Address, []byte, *big.Int, *big.Int, error) {
	return _IRMAScheme.Contract.GetIssuerById(&_IRMAScheme.CallOpts, _id)
}

// GetIssuerCredentialById is a free data retrieval call binding the contract method 0x13246ba2.
//
// Solidity: function getIssuerCredentialById(_issuerId string, _credId string) constant returns(string, string, bytes)
func (_IRMAScheme *IRMASchemeCaller) GetIssuerCredentialById(opts *bind.CallOpts, _issuerId string, _credId string) (string, string, []byte, error) {
	var (
		ret0 = new(string)
		ret1 = new(string)
		ret2 = new([]byte)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
	}
	err := _IRMAScheme.contract.Call(opts, out, "getIssuerCredentialById", _issuerId, _credId)
	return *ret0, *ret1, *ret2, err
}

// GetIssuerCredentialById is a free data retrieval call binding the contract method 0x13246ba2.
//
// Solidity: function getIssuerCredentialById(_issuerId string, _credId string) constant returns(string, string, bytes)
func (_IRMAScheme *IRMASchemeSession) GetIssuerCredentialById(_issuerId string, _credId string) (string, string, []byte, error) {
	return _IRMAScheme.Contract.GetIssuerCredentialById(&_IRMAScheme.CallOpts, _issuerId, _credId)
}

// GetIssuerCredentialById is a free data retrieval call binding the contract method 0x13246ba2.
//
// Solidity: function getIssuerCredentialById(_issuerId string, _credId string) constant returns(string, string, bytes)
func (_IRMAScheme *IRMASchemeCallerSession) GetIssuerCredentialById(_issuerId string, _credId string) (string, string, []byte, error) {
	return _IRMAScheme.Contract.GetIssuerCredentialById(&_IRMAScheme.CallOpts, _issuerId, _credId)
}

// GetIssuerCredentialIdByCredentialIndex is a free data retrieval call binding the contract method 0xa23b4302.
//
// Solidity: function getIssuerCredentialIdByCredentialIndex(_issuerId string, _credIndex uint256) constant returns(string, string, bytes)
func (_IRMAScheme *IRMASchemeCaller) GetIssuerCredentialIdByCredentialIndex(opts *bind.CallOpts, _issuerId string, _credIndex *big.Int) (string, string, []byte, error) {
	var (
		ret0 = new(string)
		ret1 = new(string)
		ret2 = new([]byte)
	)
	out := &[]interface{}{
		ret0,
		ret1,
		ret2,
	}
	err := _IRMAScheme.contract.Call(opts, out, "getIssuerCredentialIdByCredentialIndex", _issuerId, _credIndex)
	return *ret0, *ret1, *ret2, err
}

// GetIssuerCredentialIdByCredentialIndex is a free data retrieval call binding the contract method 0xa23b4302.
//
// Solidity: function getIssuerCredentialIdByCredentialIndex(_issuerId string, _credIndex uint256) constant returns(string, string, bytes)
func (_IRMAScheme *IRMASchemeSession) GetIssuerCredentialIdByCredentialIndex(_issuerId string, _credIndex *big.Int) (string, string, []byte, error) {
	return _IRMAScheme.Contract.GetIssuerCredentialIdByCredentialIndex(&_IRMAScheme.CallOpts, _issuerId, _credIndex)
}

// GetIssuerCredentialIdByCredentialIndex is a free data retrieval call binding the contract method 0xa23b4302.
//
// Solidity: function getIssuerCredentialIdByCredentialIndex(_issuerId string, _credIndex uint256) constant returns(string, string, bytes)
func (_IRMAScheme *IRMASchemeCallerSession) GetIssuerCredentialIdByCredentialIndex(_issuerId string, _credIndex *big.Int) (string, string, []byte, error) {
	return _IRMAScheme.Contract.GetIssuerCredentialIdByCredentialIndex(&_IRMAScheme.CallOpts, _issuerId, _credIndex)
}

// GetIssuerPublicKeyById is a free data retrieval call binding the contract method 0xc2c98077.
//
// Solidity: function getIssuerPublicKeyById(_issuerId string, _keyIndex uint256) constant returns(uint256, bytes)
func (_IRMAScheme *IRMASchemeCaller) GetIssuerPublicKeyById(opts *bind.CallOpts, _issuerId string, _keyIndex *big.Int) (*big.Int, []byte, error) {
	var (
		ret0 = new(*big.Int)
		ret1 = new([]byte)
	)
	out := &[]interface{}{
		ret0,
		ret1,
	}
	err := _IRMAScheme.contract.Call(opts, out, "getIssuerPublicKeyById", _issuerId, _keyIndex)
	return *ret0, *ret1, err
}

// GetIssuerPublicKeyById is a free data retrieval call binding the contract method 0xc2c98077.
//
// Solidity: function getIssuerPublicKeyById(_issuerId string, _keyIndex uint256) constant returns(uint256, bytes)
func (_IRMAScheme *IRMASchemeSession) GetIssuerPublicKeyById(_issuerId string, _keyIndex *big.Int) (*big.Int, []byte, error) {
	return _IRMAScheme.Contract.GetIssuerPublicKeyById(&_IRMAScheme.CallOpts, _issuerId, _keyIndex)
}

// GetIssuerPublicKeyById is a free data retrieval call binding the contract method 0xc2c98077.
//
// Solidity: function getIssuerPublicKeyById(_issuerId string, _keyIndex uint256) constant returns(uint256, bytes)
func (_IRMAScheme *IRMASchemeCallerSession) GetIssuerPublicKeyById(_issuerId string, _keyIndex *big.Int) (*big.Int, []byte, error) {
	return _IRMAScheme.Contract.GetIssuerPublicKeyById(&_IRMAScheme.CallOpts, _issuerId, _keyIndex)
}

// GetNumberOfIssuers is a free data retrieval call binding the contract method 0x69c05a99.
//
// Solidity: function getNumberOfIssuers() constant returns(uint256)
func (_IRMAScheme *IRMASchemeCaller) GetNumberOfIssuers(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _IRMAScheme.contract.Call(opts, out, "getNumberOfIssuers")
	return *ret0, err
}

// GetNumberOfIssuers is a free data retrieval call binding the contract method 0x69c05a99.
//
// Solidity: function getNumberOfIssuers() constant returns(uint256)
func (_IRMAScheme *IRMASchemeSession) GetNumberOfIssuers() (*big.Int, error) {
	return _IRMAScheme.Contract.GetNumberOfIssuers(&_IRMAScheme.CallOpts)
}

// GetNumberOfIssuers is a free data retrieval call binding the contract method 0x69c05a99.
//
// Solidity: function getNumberOfIssuers() constant returns(uint256)
func (_IRMAScheme *IRMASchemeCallerSession) GetNumberOfIssuers() (*big.Int, error) {
	return _IRMAScheme.Contract.GetNumberOfIssuers(&_IRMAScheme.CallOpts)
}

// Id is a free data retrieval call binding the contract method 0xaf640d0f.
//
// Solidity: function id() constant returns(string)
func (_IRMAScheme *IRMASchemeCaller) Id(opts *bind.CallOpts) (string, error) {
	var (
		ret0 = new(string)
	)
	out := ret0
	err := _IRMAScheme.contract.Call(opts, out, "id")
	return *ret0, err
}

// Id is a free data retrieval call binding the contract method 0xaf640d0f.
//
// Solidity: function id() constant returns(string)
func (_IRMAScheme *IRMASchemeSession) Id() (string, error) {
	return _IRMAScheme.Contract.Id(&_IRMAScheme.CallOpts)
}

// Id is a free data retrieval call binding the contract method 0xaf640d0f.
//
// Solidity: function id() constant returns(string)
func (_IRMAScheme *IRMASchemeCallerSession) Id() (string, error) {
	return _IRMAScheme.Contract.Id(&_IRMAScheme.CallOpts)
}

// IssuerIds is a free data retrieval call binding the contract method 0x468e9703.
//
// Solidity: function issuerIds( uint256) constant returns(string)
func (_IRMAScheme *IRMASchemeCaller) IssuerIds(opts *bind.CallOpts, arg0 *big.Int) (string, error) {
	var (
		ret0 = new(string)
	)
	out := ret0
	err := _IRMAScheme.contract.Call(opts, out, "issuerIds", arg0)
	return *ret0, err
}

// IssuerIds is a free data retrieval call binding the contract method 0x468e9703.
//
// Solidity: function issuerIds( uint256) constant returns(string)
func (_IRMAScheme *IRMASchemeSession) IssuerIds(arg0 *big.Int) (string, error) {
	return _IRMAScheme.Contract.IssuerIds(&_IRMAScheme.CallOpts, arg0)
}

// IssuerIds is a free data retrieval call binding the contract method 0x468e9703.
//
// Solidity: function issuerIds( uint256) constant returns(string)
func (_IRMAScheme *IRMASchemeCallerSession) IssuerIds(arg0 *big.Int) (string, error) {
	return _IRMAScheme.Contract.IssuerIds(&_IRMAScheme.CallOpts, arg0)
}

// Metadata is a free data retrieval call binding the contract method 0x392f37e9.
//
// Solidity: function metadata() constant returns(bytes)
func (_IRMAScheme *IRMASchemeCaller) Metadata(opts *bind.CallOpts) ([]byte, error) {
	var (
		ret0 = new([]byte)
	)
	out := ret0
	err := _IRMAScheme.contract.Call(opts, out, "metadata")
	return *ret0, err
}

// Metadata is a free data retrieval call binding the contract method 0x392f37e9.
//
// Solidity: function metadata() constant returns(bytes)
func (_IRMAScheme *IRMASchemeSession) Metadata() ([]byte, error) {
	return _IRMAScheme.Contract.Metadata(&_IRMAScheme.CallOpts)
}

// Metadata is a free data retrieval call binding the contract method 0x392f37e9.
//
// Solidity: function metadata() constant returns(bytes)
func (_IRMAScheme *IRMASchemeCallerSession) Metadata() ([]byte, error) {
	return _IRMAScheme.Contract.Metadata(&_IRMAScheme.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_IRMAScheme *IRMASchemeCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var (
		ret0 = new(common.Address)
	)
	out := ret0
	err := _IRMAScheme.contract.Call(opts, out, "owner")
	return *ret0, err
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_IRMAScheme *IRMASchemeSession) Owner() (common.Address, error) {
	return _IRMAScheme.Contract.Owner(&_IRMAScheme.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() constant returns(address)
func (_IRMAScheme *IRMASchemeCallerSession) Owner() (common.Address, error) {
	return _IRMAScheme.Contract.Owner(&_IRMAScheme.CallOpts)
}

// AddIssuer is a paid mutator transaction binding the contract method 0x6cd4b82e.
//
// Solidity: function addIssuer(_id string, _logoUrl string, _metadata bytes) returns(bool)
func (_IRMAScheme *IRMASchemeTransactor) AddIssuer(opts *bind.TransactOpts, _id string, _logoUrl string, _metadata []byte) (*types.Transaction, error) {
	return _IRMAScheme.contract.Transact(opts, "addIssuer", _id, _logoUrl, _metadata)
}

// AddIssuer is a paid mutator transaction binding the contract method 0x6cd4b82e.
//
// Solidity: function addIssuer(_id string, _logoUrl string, _metadata bytes) returns(bool)
func (_IRMAScheme *IRMASchemeSession) AddIssuer(_id string, _logoUrl string, _metadata []byte) (*types.Transaction, error) {
	return _IRMAScheme.Contract.AddIssuer(&_IRMAScheme.TransactOpts, _id, _logoUrl, _metadata)
}

// AddIssuer is a paid mutator transaction binding the contract method 0x6cd4b82e.
//
// Solidity: function addIssuer(_id string, _logoUrl string, _metadata bytes) returns(bool)
func (_IRMAScheme *IRMASchemeTransactorSession) AddIssuer(_id string, _logoUrl string, _metadata []byte) (*types.Transaction, error) {
	return _IRMAScheme.Contract.AddIssuer(&_IRMAScheme.TransactOpts, _id, _logoUrl, _metadata)
}

// AddIssuerCredential is a paid mutator transaction binding the contract method 0x16f3b1a5.
//
// Solidity: function addIssuerCredential(_issuerId string, _credentialId string, _logoUrl string, _issueSpec bytes) returns(bool)
func (_IRMAScheme *IRMASchemeTransactor) AddIssuerCredential(opts *bind.TransactOpts, _issuerId string, _credentialId string, _logoUrl string, _issueSpec []byte) (*types.Transaction, error) {
	return _IRMAScheme.contract.Transact(opts, "addIssuerCredential", _issuerId, _credentialId, _logoUrl, _issueSpec)
}

// AddIssuerCredential is a paid mutator transaction binding the contract method 0x16f3b1a5.
//
// Solidity: function addIssuerCredential(_issuerId string, _credentialId string, _logoUrl string, _issueSpec bytes) returns(bool)
func (_IRMAScheme *IRMASchemeSession) AddIssuerCredential(_issuerId string, _credentialId string, _logoUrl string, _issueSpec []byte) (*types.Transaction, error) {
	return _IRMAScheme.Contract.AddIssuerCredential(&_IRMAScheme.TransactOpts, _issuerId, _credentialId, _logoUrl, _issueSpec)
}

// AddIssuerCredential is a paid mutator transaction binding the contract method 0x16f3b1a5.
//
// Solidity: function addIssuerCredential(_issuerId string, _credentialId string, _logoUrl string, _issueSpec bytes) returns(bool)
func (_IRMAScheme *IRMASchemeTransactorSession) AddIssuerCredential(_issuerId string, _credentialId string, _logoUrl string, _issueSpec []byte) (*types.Transaction, error) {
	return _IRMAScheme.Contract.AddIssuerCredential(&_IRMAScheme.TransactOpts, _issuerId, _credentialId, _logoUrl, _issueSpec)
}

// AddIssuerPublicKey is a paid mutator transaction binding the contract method 0x35ec27c4.
//
// Solidity: function addIssuerPublicKey(_issuerId string, _key bytes) returns(bool)
func (_IRMAScheme *IRMASchemeTransactor) AddIssuerPublicKey(opts *bind.TransactOpts, _issuerId string, _key []byte) (*types.Transaction, error) {
	return _IRMAScheme.contract.Transact(opts, "addIssuerPublicKey", _issuerId, _key)
}

// AddIssuerPublicKey is a paid mutator transaction binding the contract method 0x35ec27c4.
//
// Solidity: function addIssuerPublicKey(_issuerId string, _key bytes) returns(bool)
func (_IRMAScheme *IRMASchemeSession) AddIssuerPublicKey(_issuerId string, _key []byte) (*types.Transaction, error) {
	return _IRMAScheme.Contract.AddIssuerPublicKey(&_IRMAScheme.TransactOpts, _issuerId, _key)
}

// AddIssuerPublicKey is a paid mutator transaction binding the contract method 0x35ec27c4.
//
// Solidity: function addIssuerPublicKey(_issuerId string, _key bytes) returns(bool)
func (_IRMAScheme *IRMASchemeTransactorSession) AddIssuerPublicKey(_issuerId string, _key []byte) (*types.Transaction, error) {
	return _IRMAScheme.Contract.AddIssuerPublicKey(&_IRMAScheme.TransactOpts, _issuerId, _key)
}
