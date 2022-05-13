package abfplugin

import (
	govppapi "git.fd.io/govpp.git/api"
	//"github.com/go-errors/errors"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/cn-infra/utils/safeclose"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	"github.com/ligato/vpp-agent/plugins/govppmux"
	"github.com/ligato/vpp-agent/plugins/vpp/abfplugin/abfidx"
	"github.com/ligato/vpp-agent/plugins/vpp/abfplugin/vppcalls"
	"github.com/ligato/vpp-agent/plugins/vpp/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/vpp/model/abf"
	"fmt"
	"github.com/ligato/vpp-agent/plugins/vpp/aclplugin/aclidx"
)
type ABFConfigurator struct {
	log logging.Logger

	// In-memory mappings
	ifIndexes      	ifaceidx.SwIfIndex
	AbfIndexes   	abfidx.ABFIndexRW
	AclIndexesL2      aclidx.ACLIndexRW
	AclIndexesL3L4      aclidx.ACLIndexRW


	// Cache for ACL un-configured interfaces
	//ifCache []*ACLIfCacheEntry

	// VPP channels
	vppChan     	govppapi.Channel
	vppDumpChan 	govppapi.Channel

	// ACL VPP calls handler
	abfHandler 	*vppcalls.ABFVppHandler
	
	abfIndex  	uint32
}

func (c *ABFConfigurator) Init(logger logging.PluginLogger, goVppMux govppmux.API, swIfIndexes ifaceidx.SwIfIndex,AclIndexL2Handler aclidx.ACLIndexRW ,AclIndexL3L4Handler aclidx.ACLIndexRW ) (err error) {
	// Logger
	c.log = logger.NewLogger("abf-plugin")

	// Mappings
	c.ifIndexes = swIfIndexes
	c.AbfIndexes = abfidx.NewABFIndex(nametoidx.NewNameToIdx(c.log, "abf_indexes", nil))
	c.AclIndexesL2 = AclIndexL2Handler
	c.AclIndexesL3L4 = AclIndexL3L4Handler

	// VPP channels
	c.vppChan, err = goVppMux.NewAPIChannel()
	if err != nil {
		return fmt.Errorf("failed to create API channel: %v", err)
	}
	c.vppDumpChan, err = goVppMux.NewAPIChannel()
	if err != nil {
		return fmt.Errorf("failed to create dump API channel: %v", err)
	}

	// ACL binary api handler
	c.abfHandler = vppcalls.NewABFVppHandler(c.vppChan, c.vppDumpChan)
	c.abfIndex = 0
	c.log.Infof("ABF configurator initialized")

	return nil
}

// Close GOVPP channel.
//func (c *ABFConfigurator) AddPolicyABF(policy *abf.Abf_Abf_Policy,abf string)(uint32, error){
//	return 0,nil
//}
func (c *ABFConfigurator) Close() error {
	if err := safeclose.Close(c.vppChan, c.vppDumpChan); err != nil {
		return c.LogError(fmt.Errorf("failed to safeclose interface configurator: %v", err))
	}
	return nil
}

// clearMapping prepares all in-memory-mappings and other cache fields. All previous cached entries are removed.
func (c *ABFConfigurator) clearMapping() {
	c.AbfIndexes.Clear()
}

// GetAbfIndexes exposes ABF name-to-index mapping
func (c *ABFConfigurator) GetAbfIndexes() abfidx.ABFIndexRW {
	return c.AbfIndexes
}

func (c *ABFConfigurator) GetIndex() uint32 {
	c.abfIndex=c.abfIndex+1
	return c.abfIndex
}

func (c *ABFConfigurator) ConfigureABF(abf *abf.Abf) error {
	if len(abf.AbfPolicy.Path) == 0 {
		 fmt.Println("failed to configure ABF, no policy path to set, create policy")
	return nil
	 }
	aclIndex,_, exist := c.AclIndexesL2.LookupIdx(abf.AbfPolicy.AclName)
	if !exist{
		 index,_, exist := c.AclIndexesL3L4.LookupIdx(abf.AbfPolicy.AclName)
		 if !exist{
			fmt.Println("no acl rule set of this name:", abf.AbfPolicy.AclName)
			 return nil

		}else{
			aclIndex = index-1
                //fmt.Println("L3L4",aclIndex)

		}
	}else {
		aclIndex = aclIndex-1
		//fmt.Println("L2",aclIndex)
	}
	abfIndex := c.GetIndex()
	c.AbfIndexes.RegisterName(abf.AbfPolicy.PolicyName, abfIndex, abf)
	_ , _ = c.abfHandler.AddPolicyABF(abf.AbfPolicy,abf.AbfName,aclIndex,abfIndex,1)
// configuraing Interfaces
if ifaces := abf.GetAbfInterface(); ifaces!=nil{
	abfIndex,_, exist := c.AbfIndexes.LookupIdx(newABF.AbfInterface.PolicyName)
	if !exist{
		c.log.Info("no abf policy set of this name:", abf.AbfInterface.PolicyName)
			 return nil
}
	abfIfIndices, exist := c.getInterfaces(abf.AbfInterface.InterfaceName)	
if !exist{
		c.log.Info("no interface set of this name:", abf.AbfInterface.InterfaceName)
			 return nil
}
if abf.AbfInterface.IsIpv6 {
	IsIpv6 := 1
}else{
	IsIpv6 := 0
}
err := c.abfHandler.SetABFToInterface(abfIndex,abfIfIndices,IsIpv6,1)
if err != nil {
				return fmt.Errorf("failed to set ABF %s to interface(s) %v: %v",newABF.AbfInterface.PolicyName, abf.AbfInterface.InterfaceName, err)
}
}
	return nil
}
func (c *ABFConfigurator) LogError(err error) error {
	if err == nil {
		return nil
	}
	//c.log.WithField("logger", c.log).Errorf(string(err.Error() + "\n" + string(err.(*err.Error).Stack())))
	return err
}
// ModifyABF modifies previously created ABF.
// List of interfaces is refreshed as well.
func (c *ABFConfigurator) ModifyABF(oldABF, newABF *abf.Abf) error {
if newABF.AbfPolicy !=nil{
	if len(newABF.AbfPolicy.Path) == 0 {
		 fmt.Println("failed to configure ABF, no policy path to set, create policy")
	return nil
	 }
	abfIndex,_, exist := c.AbfIndexes.LookupIdx(newABF.AbfPolicy.PolicyName)
	if !exist{
	fmt.Println("no abf policy set of this name:", newABF.AbfPolicy.PolicyName)
			 return nil
}
	aclIndex,_, exist := c.AclIndexesL2.LookupIdx(newABF.AbfPolicy.AclName)
	if !exist{
		 index,_, exist := c.AclIndexesL3L4.LookupIdx(newABF.AbfPolicy.AclName)
		 if !exist{
			fmt.Println("no acl rule set of this name:", abf.AbfPolicy.AclName)
			 return nil

		}else{
			aclIndex = index-1
                //fmt.Println("L3L4",aclIndex)

		}
	}else {
		aclIndex = aclIndex-1
		//fmt.Println("L2",aclIndex)
	}
//not creating new abfIndex means modifying the existing one
	_ , _ = c.abfHandler.AddPolicyABF(newABF.AbfPolicy,newABF.AbfName,aclIndex,abfIndex,1)
}
c.log.Info("ABF %s modified", newABF.AbfName)

return nil	
}
// DeleteABF removes existing ABF. To detach ABF from interfaces, list of interfaces has to be provided.
func (c *ABFConfigurator) DeleteABF(abf *abf.Abf) error {
//	abfIndex,_, exist := c.AbfIndexes.LookupIdx(abf.AbfPolicy.PolicyName)
//	if !exist{
//	fmt.Println("no abf policy set of this name:", abf.AbfPolicy.PolicyName)
//			 return nil
//}
//	err := c.abfHandler.DeleteABFPolicy(abfIndex,abf.AbfPolicy)
//		if err != nil {
//			return c.log.Info("failed to remove MAC IP ACL %s: %v", acl.AclName, err)

//}

c.AbfIndexes.UnregisterName(abf.AbfPolicy.PolicyName)
//c.log.Debugf("ACL %s unregistered from L2 mapping", acl.AclName)


}

func (c *ABFConfigurator) getInterfaces(name string) (uint32, bool) {
	
		ifIdx, _, found := c.ifIndexes.LookupIdx(name)
		if !found {
			return 0,false	
		}else{
			return ifIdx,true
		}
		
}
