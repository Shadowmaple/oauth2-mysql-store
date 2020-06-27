package clientStore

import (
	"context"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/oauth2.v4/models"
)

func TestClientStore(t *testing.T) {
	Convey("Test client store:", t, func() {
		store := NewClientStore(DefaultConfig())
		defer store.Close()

		// Convey("Test Get", func() {
		ctx := context.Background()
		info := &models.Client{
			ID:     "22222",
			Secret: "231udna_dfe",
			Domain: "www.example.com",
		}
		err := store.Create(info)
		So(err, ShouldBeNil)

		clientInfo, err := store.GetByID(ctx, info.ID)
		So(err, ShouldBeNil)
		So(clientInfo.GetSecret(), ShouldEqual, info.Secret)

		clientInfo, err = store.GetByDomain(info.Domain)
		So(err, ShouldBeNil)
		So(clientInfo.GetSecret(), ShouldEqual, info.Secret)
		// })
	})
}
