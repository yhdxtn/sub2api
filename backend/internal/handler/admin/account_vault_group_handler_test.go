package admin

import (
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountVaultGroupMissingNameMustNotRemoveGroups(t *testing.T) {
	for _, body := range []string{
		`{"ids":[1]}`, `{"ids":[1],"group_name":null}`,
		`{"ids":[1],"group_name":"","group_name":"test"}`,
		`{"ids":[1],"group_name":"test","unexpected":"private-canary"}`,
	} {
		writer := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(writer)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/account-vault/groups/assign", strings.NewReader(body))
		(&AccountVaultHandler{}).AssignGroup(c)
		require.Equal(t, http.StatusBadRequest, writer.Code)
		require.NotContains(t, writer.Body.String(), "private-canary")
	}
}
