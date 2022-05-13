package vppcalls

import (
	"testing"

	//abf_api "github.com/ligato/vpp-agent/plugins/vpp/binapi/abf"
	"github.com/ligato/vpp-agent/plugins/vpp/model/abf"
	"github.com/ligato/vpp-agent/tests/vppcallmock"
	. "github.com/onsi/gomega"
)

var Abfs = abf.Abf{

                AbfName : "abf1",
                AbfPolicy : &abf.Abf_Abf_Policy{

                        PolicyName : "policy1",
                        AclName : "acl1",
                        Path  : []*abf.Abf_Abf_Policy_Paths{
                                {
                                        NextHopAdd: "192.168.2.0/24",

                                },
                                        
                        },

                },
        }

func TestAddIPAcl(t *testing.T) {
	ctx := vppcallmock.SetupTestCtx(t)
	defer ctx.TeardownTestCtx()
	abfHandler := NewABFVppHandler(ctx.MockChannel, ctx.MockChannel)

	_, err := abfHandler.AddPolicyABF(Abfs.AbfPolicy, "abf0")
	Expect(err).To(BeNil())

}
