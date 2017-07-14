package bxmpp

import (
	"crypto/tls"
	"github.com/42wim/matterbridge/bridge/config"
	log "github.com/Sirupsen/logrus"
	"github.com/mattn/go-xmpp"

	"strings"
	"time"
)

type Bxmpp struct {
	xc      *xmpp.Client
	xmppMap map[string]string
	Config  *config.Protocol
	Remote  chan config.Message
	Account string

	// XIL
	xmppClients   map[string]*xmpp.Client
	Channel string
	Users map[string]bool
	UserToXmpp map[string]string
}

var flog *log.Entry
var protocol = "xmpp"



func init() {
	flog = log.WithFields(log.Fields{"module": protocol})
}

func New(cfg config.Protocol, account string, c chan config.Message) *Bxmpp {
	b := &Bxmpp{}
	b.xmppMap = make(map[string]string)
	b.Config = &cfg
	b.Account = account
	b.Remote = c
	b.xmppClients = make(map[string]*xmpp.Client)
	b.Users = make(map[string]bool)
	b.UserToXmpp = make(map[string]string)
	return b
}

func (b *Bxmpp) Connect() error {
	var err error
	flog.Infof("Connecting %s", b.Config.Server)
	b.xc, err = b.createXMPP()
	if err != nil {
		flog.Debugf("%#v", err)
		return err
	}
	flog.Info("Connection succeeded")
	go b.handleXmpp()
	return nil
}

func (b *Bxmpp) Disconnect() error {
	return nil
}

func (b *Bxmpp) JoinChannel(channel string) error {
	b.xc.JoinMUCNoHistory(channel+"@"+b.Config.Muc, b.Config.Nick)
	b.Channel = channel
	return nil
}

func (b *Bxmpp) Send(msg config.Message) error {
	flog.Debugf("Receiving %#v", msg)
	var client *xmpp.Client
	var ok bool
	mmUser := msg.Username[1:len(msg.Username)-2]
	xmppUser := mmUser

	if b.UserToXmpp[mmUser] == "" {
		// User hasn't been mapped out yet. Let's find a free username to map against:
		if b.xmppClients[xmppUser] == nil {
			for b.Users[xmppUser] {
				// there's someone in the xmpp muc with the same nick as in mm
				xmppUser += "_mm"
			}
		}
		b.UserToXmpp[mmUser] = xmppUser
	} else {
		xmppUser = b.UserToXmpp[mmUser]
	}

	flog.Infof("1")
	if client, ok = b.xmppClients[xmppUser]; !ok {
		flog.Infof("2")
		// Connect and join channel
		tc := new(tls.Config)
		tc.InsecureSkipVerify = b.Config.SkipTLSVerify
		tc.ServerName = strings.Split(b.Config.Server, ":")[0]
		options := xmpp.Options{
			Host:      b.Config.Server,
			User:      b.Config.Jid,
			Password:  b.Config.Password,
			NoTLS:     true,
			StartTLS:  true,
			TLSConfig: tc,
	
			//StartTLS:      false,
			Debug:                        true,
			Session:                      true,
			Status:                       "",
			StatusMessage:                "",
			Resource:                     xmppUser,
			InsecureAllowUnencryptedAuth: false,
			//InsecureAllowUnencryptedAuth: true,
		}
		var err error
		flog.Infof("3")
		client, err = options.NewClient()
		if err != nil {
			flog.Infof("OoOoops")
			flog.Infof(err.Error())
		}
		flog.Infof("4")
		b.xmppClients[xmppUser] = client
		flog.Infof("5")
		client.JoinMUCNoHistory(b.Channel+"@"+b.Config.Muc, xmppUser)
		b.xmppKeepAlive(client)
	}
	flog.Infof("6")

	client.Send(xmpp.Chat{Type: "groupchat", Remote: msg.Channel + "@" + b.Config.Muc, Text: msg.Text})
	return nil
}

func (b *Bxmpp) createXMPP() (*xmpp.Client, error) {
	tc := new(tls.Config)
	tc.InsecureSkipVerify = b.Config.SkipTLSVerify
	tc.ServerName = strings.Split(b.Config.Server, ":")[0]
	options := xmpp.Options{
		Host:      b.Config.Server,
		User:      b.Config.Jid,
		Password:  b.Config.Password,
		NoTLS:     true,
		StartTLS:  true,
		TLSConfig: tc,

		//StartTLS:      false,
		Debug:                        true,
		Session:                      true,
		Status:                       "",
		StatusMessage:                "",
		Resource:                     "bridge",
		InsecureAllowUnencryptedAuth: false,
		//InsecureAllowUnencryptedAuth: true,
	}
	var err error
	b.xc, err = options.NewClient()
	return b.xc, err
}

func (b *Bxmpp) xmppKeepAlive(client *xmpp.Client) chan bool {
	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(90 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				client.PingC2S("", "")
			case <-done:
				return
			}
		}
	}()
	return done
}

func (b *Bxmpp) handleXmpp() error {
	done := b.xmppKeepAlive(b.xc)
	defer close(done)
	nodelay := time.Time{}
	for {
		m, err := b.xc.Recv()
		if err != nil {
			return err
		}
		switch v := m.(type) {
		case xmpp.Chat:
			var channel, nick string
			if v.Type == "groupchat" {
				s := strings.Split(v.Remote, "@")
				if len(s) >= 2 {
					channel = s[0]
				}
				s = strings.Split(s[1], "/")
				if len(s) == 2 {
					nick = s[1]
				}
				if nick != b.Config.Nick && b.xmppClients[nick] == nil && v.Stamp == nodelay && v.Text != "" {
					flog.Debugf("Sending message from %s on %s to gateway", nick, b.Account)
					b.Remote <- config.Message{Username: nick, Text: v.Text, Channel: channel, Account: b.Account, UserID: v.Remote}
				}
			}
		case xmpp.Presence:
			flog.Debugf("presence!")
			flog.Debugf("%v", v)
			flog.Debugf("--- %s, %s, %s, %s, %s---", v.From, v.To, v.Type, v.Show, v.Status)
			status := true
			if v.Type == "unavailable" {
				status = false
			}
			var nick string
			s := strings.Split(v.From, "@")
			s = strings.Split(s[1], "/")
			if len(s) == 2 {
				nick = s[1]
			}
			b.Users[nick] = status
			flog.Debugf("Setting b.Users[%s]=%v", nick, status)
			flog.Debugf("%v", b.Users)
		}
	}
}
