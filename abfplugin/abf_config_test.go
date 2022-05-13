package abfplugin_test

import (
	"git.fd.io/govpp.git/adapter/mock"
	"git.fd.io/govpp.git/core"
	"github.com/ligato/cn-infra/logging"
	"github.com/ligato/vpp-agent/idxvpp/nametoidx"
	"github.com/ligato/vpp-agent/plugins/vpp/abfplugin"
//	abf_api "github.com/ligato/vpp-agent/plugins/vpp/binapi/abf"
	//"github.com/ligato/vpp-agent/plugins/vpp/binapi/vpe"
	"github.com/ligato/vpp-agent/plugins/vpp/ifplugin/ifaceidx"
	"github.com/ligato/vpp-agent/plugins/vpp/model/abf"
	"github.com/ligato/vpp-agent/tests/vppcallmock"
	. "github.com/onsi/gomega"
	"testing"
)

var abfdata = abf.Abf{
	 AbfName :    "abf1",
	 AbfPolicy :  &abf.Abf_Abf_Policy{
	 PolicyName : "policy1",
                        AclName : "acl1",
                        Path  : []*abf.Abf_Abf_Policy_Paths{
                                {
                                        NextHopAdd: "192.168.2.0",

                                },
                                        
                        },

},
	AbfInterface: &abf.Abf_Abf_Interface{},
}

func TestConfigureABF(t *testing.T) {
	_, _, plugin := aclTestSetup(t, false)
	//defer aclTestTeardown(connection, plugin)
	// ipAcl Replies
	//ctx.MockVpp.MockReply(&acl_api.ACLAddReplaceReply{})

	// Test configure ipAcl
	err := plugin.ConfigureABF(&abfdata)
	Expect(err).To(BeNil())

	// macipAcl Replies
	//ctx.MockVpp.MockReply(&acl_api.MacipACLAddReply{})

	// Test configure macipAcl
	err = plugin.ConfigureABF(&abfdata)
	Expect(err).To(BeNil())
}

func aclTestSetup(t *testing.T, createIfs bool) (*vppcallmock.TestCtx, *core.Connection, *abfplugin.ABFConfigurator) {
	RegisterTestingT(t)

	 ctx := &vppcallmock.TestCtx{
                MockVpp: &mock.VppAdapter{},
        }
        connection, err := core.Connect(ctx.MockVpp)
        Expect(err).ShouldNot(HaveOccurred())


	// Logger
	log := logging.ForPlugin("test-log")
	log.SetLevel(logging.DebugLevel)

	// Interface indices
	ifIndexes := ifaceidx.NewSwIfIndex(nametoidx.NewNameToIdx(log, "acl-plugin", nil))
	if createIfs {
		ifIndexes.RegisterName("if1", 1, nil)
		ifIndexes.RegisterName("if2", 2, nil)
		ifIndexes.RegisterName("if3", 3, nil)
		ifIndexes.RegisterName("if4", 4, nil)
	}

	// Configurator
	plugin := &abfplugin.ABFConfigurator{}
	err = plugin.Init(log, connection, ifIndexes)
	Expect(err).To(BeNil())

	return ctx, connection, plugin
}


