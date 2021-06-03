package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/policy"
	"github.com/hyperledger/fabric/core/policyprovider"
	"github.com/hyperledger/fabric/msp/mgmt"
	"github.com/hyperledger/fabric/protos/msp"
	pb "github.com/hyperledger/fabric/protos/peer"
	"math/rand"
	"strconv"
	"time"
)

const (
	SENDCHANGEPB = "sendChangePB"
	GETCHANGGEPB = "getChangePB"
	GETALLCHANGE = "getAllChange"
	SENDSIGN     = "sendSign"
	GETALLSIGN   = "getAllSign"
)

var logger = shim.NewLogger("MultiSignatureSysCC")

type ChangeRequest struct {
	ChannelId    string    `json:"channel_id"`    //baas平台业务链ID
	ChangePB     string    `json:"change_pb"`     //配置变更文件（十六进制字符串）
	SignCount    int       `json:"sign_count"`    //已签名数
	OrgSum       int       `json:"org_sum"`       //业务链机构数
	State        int       `json:"state"`         //请求状态(0:未完成1:已完成)
	Organization string    `json:"organization"`  //机构MSPId
	CreateTime   time.Time `json:"create_time"`   //创建时间
	CompleteTime time.Time `json:"complete_time"` //完成时间
}

type SignBody struct {
	Sign         string    `json:"sign"`         //签名信息（十六进制字符串）
	Organization string    `json:"organization"` //机构MSPId
	SignTime     time.Time `json:"sign_time"`    //签名时间
}

// New returns an implementation of the chaincode interface
func New() shim.Chaincode {
	return &MultiSignatureSysCC{
		PolicyChecker: policyprovider.GetPolicyChecker(),
	}
}

// MultiSignatureSysCC for scc plugin test
type MultiSignatureSysCC struct {
	// PolicyChecker is the interface used to perform
	// access control
	PolicyChecker policy.PolicyChecker
}

// Init implements the chaincode shim interface
func (s *MultiSignatureSysCC) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Info("Init Success")
	return shim.Success(nil)
}

// Invoke implements the chaincode shim interface
func (s *MultiSignatureSysCC) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	if len(args) < 1 {
		return shim.Error(fmt.Sprintf("invalid number of arguments to msscc: %d", len(args)))
	}

	// Handle ACL:
	// 1. get the signed proposal
	sp, err := stub.GetSignedProposal()
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed retrieving signed proposal on executing %s with error %s", function, err))
	}
	switch function {
	case SENDCHANGEPB:
		fmt.Println("调用SENDCHANGEPB方法")
		if err = s.PolicyChecker.CheckPolicyNoChannel(mgmt.Admins, sp); err != nil {
			return shim.Error(fmt.Sprintf("没有管理员签名 [%s]: %s", function, err))
		}
		return sendChangePB(stub, args)
	case GETCHANGGEPB:
		fmt.Println("调用GETCHANGGEPB方法")
		return getChangePB(stub, args)
	case GETALLCHANGE:
		fmt.Println("调用GETALLCHANGE方法")
		return getAllChange(stub)
	case SENDSIGN:
		fmt.Println("调用SENDSIGN方法")
		if err = s.PolicyChecker.CheckPolicyNoChannel(mgmt.Admins, sp); err != nil {
			return shim.Error(fmt.Sprintf("没有管理员签名 [%s]: %s", function, err))
		}
		return sendSign(stub, args)
	case GETALLSIGN:
		fmt.Println("调用GETALLSIGN方法")
		return getAllSign(stub, args)
	default:
		return shim.Error(fmt.Sprintf("没有%s方法", function))
	}

}

// 储存变更文件pb，pb以base64格式存储
func sendChangePB(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	//键值：待配置的通道code加16位随机数，例：yychannel_123456789987654321
	key := stub.GetChannelID() + "_" + CreateCaptcha()
	//获取提交者MSP信息
	mspId := (&msp.SerializedIdentity{}).GetMspid()
	orgsum, _ := strconv.Atoi(args[2])
	//构建配置变更数据
	cr := &ChangeRequest{
		ChannelId:    args[0],
		ChangePB:     args[1],
		SignCount:    1,
		OrgSum:       orgsum,
		State:        0,
		Organization: mspId,
		CreateTime:   time.Now(),
		CompleteTime: nil,
	}
	crJson, err := json.Marshal(cr)
	if err != nil {
		return shim.Error(fmt.Sprintf("Parse failure to ChangeRequest : %v", cr))
	}
	err = stub.PutState(key, crJson)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to sendChangePB : %s", args[0]))
	}
	//设置配置变更Event事件，Baas平台监听到此事件后获得配置变更数据
	eventKey := "config_event_" + stub.GetChannelID()
	stub.SetEvent(eventKey, crJson)
	//返回构建的配置变更数据
	return shim.Success(crJson)
}

//获取该通道所有变更列表
func getAllChange(stub shim.ChaincodeStubInterface) pb.Response {

	startKey := stub.GetChannelID() + "_" + "0000000000000000"
	endKey := stub.GetChannelID() + "_" + "9999999999999999"

	resultsIterator, err := stub.GetStateByRange(startKey, endKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	// buffer is a JSON array containing QueryResults
	var buffer bytes.Buffer
	buffer.WriteString("[")
	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Value\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")
	fmt.Printf("- getAllChange:\n%s\n", buffer.String())

	return shim.Success(buffer.Bytes())
}

// 获取变更文件pb
func getChangePB(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	value, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed to get key: %s with error: %s", args[0], err))
	}
	if value == nil {
		return shim.Error(fmt.Sprintf("Result not found: %s", args[0]))
	}
	return shim.Success(value)
}

// 储存变更文件pb，pb以base64格式存储
func sendSign(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	key := args[0] + "_sign"
	creatorByte, _ := stub.GetCreator()
	// 构造SerializedIdentity方法，并将creator进行Unmarshal
	si := &msp.SerializedIdentity{}
	err := proto.Unmarshal(creatorByte, si)
	if err != nil {
		return shim.Error("反序列化Creator失败")
	}
	fmt.Println("MSPID: " + si.GetMspid())
	fmt.Println("Cert: " + string(si.GetIdBytes()))
	x509Cert, err := byteToCert(si.GetIdBytes())
	if err != nil {
		return shim.Error("解析签名证书失败")
	}
	fmt.Println("签名证书机构：", x509Cert.Subject.Organization)

	sb := &SignBody{
		Sign:         args[1],
		Organization: si.GetMspid(),
	}
	sbByte, err := json.Marshal(sb)
	if err != nil {
		return shim.Error("序列化SignBody失败")
	}
	err = stub.PutState(key, sbByte)
	if err != nil {
		return shim.Error(fmt.Sprintf("PutState失败！key：%s", args[0]))
	}
	fmt.Println("发送通道变更pb：", args[0])
	return shim.Success(nil)
}

func getAllSign(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	key := args[0] + "_sign"
	iter, err := stub.GetHistoryForKey(key)
	if err != nil {
		return shim.Error(fmt.Sprintf("Failed obtain %s sign!", key))
	}
	defer iter.Close()
	var logs []SignBody
	for iter.HasNext() {
		res, err := iter.Next()
		if err != nil {
			return shim.Error(fmt.Sprint("not sign History!"))
		}
		var log SignBody
		_ = json.Unmarshal(res.Value, &log)
		logs = append(logs, log)
	}
	byteLogs, err := json.Marshal(logs)
	return shim.Success(byteLogs)
}

//生成16位随机数
func CreateCaptcha() string {
	return fmt.Sprintf("%08v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(10000000000000000))
}

func byteToCert(b []byte) (cert *x509.Certificate, err error) {

	certStart := bytes.IndexAny(b, "-----BEGIN")
	if certStart == -1 {
		return nil, errors.New("No certificate found")
	}
	certText := b[certStart:]
	bl, _ := pem.Decode(certText)
	if bl == nil {
		return nil, errors.New("Could not decode the PEM structure")
	}

	cert, err = x509.ParseCertificate(bl.Bytes)
	if err != nil {
		return nil, errors.New("ParseCertificate failed")
	}

	return
}

func main() {}
