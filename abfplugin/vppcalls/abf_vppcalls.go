package vppcalls

import (
	"fmt"
	"net"
	"strings"

	govppapi "git.fd.io/govpp.git/api"
	abfapi "github.com/ligato/vpp-agent/plugins/vpp/binapi/abf"
	"github.com/ligato/vpp-agent/plugins/vpp/model/abf"
)

// GetABFPluginVersion retrieves ABF plugin version.
func GetABFPluginVersion(ch govppapi.Channel) (string, error) {
	req := &abfapi.AbfPluginGetVersion{}
	reply := &abfapi.AbfPluginGetVersionReply{}

	if err := ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return "", fmt.Errorf("failed to get VPP ABF plugin version: %v", err)
	}

	version := fmt.Sprintf("%d.%d", reply.Major, reply.Minor)

	return version, nil
}

func (h *ABFVppHandler)AddPolicyABF(policy *abf.Abf_Abf_Policy,abfName string,aclIndex uint32,abfIndex uint32,isAdd uint8)(int32, error){
	//if abfPath := policy.GetPath(); abfPath != nil{
	//	return 0 , fmt.Errorf("failed to write ABF no Path %v", abfName)
	//}
	abfApiPaths,err := ResloveABFFibPaths(policy.Path)
	if err != nil {
		return 0, err
	}
	if len(abfApiPaths) == 0 {
		return 0, fmt.Errorf("no rules found for ABF %v", abfName)
	}
	abfPolicy := &abfapi.AbfPolicy{
		PolicyID: uint32(abfIndex),
		ACLIndex: uint32(aclIndex),
		NPaths: uint8(len(abfApiPaths)),
		Paths: abfApiPaths,
	}
	fmt.Println(*abfPolicy)
	req := &abfapi.AbfPolicyAddDel{
		IsAdd: uint8(isAdd),
		Policy: *abfPolicy,
	}
	reply := &abfapi.AbfPolicyAddDelReply{}
	if err = h.callsChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return 0, fmt.Errorf("failed to write ABF %v: %v", abfName, err)
	} else if reply.Retval != 0 {
		return 0, fmt.Errorf("%s returned %v while writing ABF %v to VPP", reply.GetMessageName(), reply.Retval, abfName)
	}

	return reply.Retval, nil
}
func ResloveABFFibPaths(paths []*abf.Abf_Abf_Policy_Paths)(abfApiPaths []abfapi.FibPath, erro error){

	var (
		err        error
		nextHop      net.IP
	)
	for _, path := range paths {
			abfPolicy := &abfapi.FibPath{
				SwIfIndex: uint32(path.InterfaceIndex),
			}
		if path.IsLocal{
			abfPolicy.IsLocal = uint8(1)
		}else{
			abfPolicy.IsLocal = uint8(0)
		}
		if strings.TrimSpace(path.NextHopAdd) != "" {
			nextHop,_, err=net.ParseCIDR(path.NextHopAdd)
			if err != nil {
				return nil, err

				}
			if nextHop.To4() == nil && nextHop.To16() == nil {
				return nil, fmt.Errorf("NextHop address %v is invalid", path.NextHopAdd)
				}
			if nextHop.To4() != nil{
				abfPolicy.NextHop=nextHop.To4()
			}else{
				abfPolicy.NextHop=nextHop.To16()
				}
			}
			abfApiPaths = append(abfApiPaths, *abfPolicy)
	}

	return abfApiPaths, nil
}
