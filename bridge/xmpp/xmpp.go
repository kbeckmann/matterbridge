package bxmpp

import (
	"crypto/tls"
	"github.com/42wim/matterbridge/bridge/config"
	log "github.com/Sirupsen/logrus"
	"github.com/mattn/go-xmpp"
	"github.com/microcosm-cc/bluemonday"
	"github.com/russross/blackfriday"

	"fmt"
	"html"
	"strings"
	"time"
	"errors"
)

type Channel struct {
	Name        string
	Users       map[string]bool
	MMToXmpp  map[string]string
	XmppToMM map[string]string
}

type Bxmpp struct {
	xc      *xmpp.Client
	xmppMap map[string]string
	Config  *config.Protocol
	Remote  chan config.Message
	Account string

	// XIL
	XmppClients map[string]*xmpp.Client
	Channels map[string]*Channel
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
	b.XmppClients = make(map[string]*xmpp.Client)
	b.Channels = make(map[string]*Channel)
	flog.Infof("###################### Bxmpp.New()")
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
	b.Channels[channel] = &Channel{
		Name: channel,
		Users: make(map[string]bool),
		MMToXmpp: make(map[string]string),
		XmppToMM: make(map[string]string),
	}
	return nil
}

func (b *Bxmpp) Send(msg config.Message) error {
	var client *xmpp.Client
	var ok bool
	var channel *Channel

	flog.Debugf("Receiving %#v", msg)

	// If we haven't joined the channel, bail out!
	if channel, ok = b.Channels[msg.Channel]; !ok {
		flog.Errorf("Tried to send message but we aren't in the channel! [%s]", msg.Channel)
		return errors.New("Got message from bad channel")
	}
	flog.Debugf("Current channel %#v", channel)
		

	mmUser := msg.Username[1 : len(msg.Username)-2]
	xmppUser := mmUser

	if client, ok = b.XmppClients[mmUser]; !ok {
		// User doesn't have an xmpp client yet
		if channel.MMToXmpp[mmUser] == "" {
			// User hasn't been mapped out yet. Let's find a free username to map against:
			for channel.Users[xmppUser] {
				// there's someone in the xmpp muc with the same nick as in mm
				xmppUser += "_mm"
			}
		
			channel.MMToXmpp[mmUser] = xmppUser
			channel.XmppToMM[xmppUser] = mmUser
		} else {
			xmppUser = channel.MMToXmpp[mmUser]
		}
	} else {
		// Ensure that the MUC is joined
		flog.Infof("BONUS JOIN!!! %s", msg.Channel)
		client.JoinMUCNoHistory(msg.Channel+"@"+b.Config.Muc, xmppUser)
	}

	flog.Infof("1")
	if client, ok = b.XmppClients[mmUser]; !ok {
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
			flog.Errorf(err.Error())
		}
		flog.Infof("4")
		b.XmppClients[mmUser] = client
		flog.Infof("5")
		client.JoinMUCNoHistory(msg.Channel+"@"+b.Config.Muc, xmppUser)
		b.xmppKeepAlive(client)
	}
	flog.Infof("6")

	rawText := strings.TrimSpace(msg.Text)

	borkedURLPrefix := "http://localhost:8065/"
	correctURLPrefix := "https://mattermost.xil.se/"
	rawText = strings.Replace(rawText, borkedURLPrefix, correctURLPrefix, 1)

	//markdownBytes := blackfriday.MarkdownCommon([]byte(rawText))
	markdownBytes := blackfriday.MarkdownBasic([]byte(rawText))
	markdown := strings.TrimSpace(string(markdownBytes))
	flog.Infof("MARKDOWN: [%s]", markdown)

	if strings.HasPrefix(markdown, "<p>") && strings.HasSuffix(markdown, "</p>") {
		flog.Infof("starts with <p>..")
		flog.Infof("[%s] vs [%s]", html.UnescapeString(markdown[3:len(markdown)-4]), rawText)

		if html.UnescapeString(markdown[3:len(markdown)-4]) == rawText {
			// No markdown in the text!
			flog.Infof("No markdown! woop!")
			chat := xmpp.Chat{Type: "groupchat", Remote: msg.Channel + "@" + b.Config.Muc, Text: rawText}
			client.Send(chat)
			return nil
		}
	}

	// HTML
	sanitizedBytes := bluemonday.UGCPolicy().SanitizeBytes(markdownBytes)
	sanitized := strings.TrimSpace(string(sanitizedBytes))
	xmppHtml := fmt.Sprintf("<body>%s</body><html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'>%s</body></html>", rawText, sanitized)
	//chat := xmpp.Chat{Type: "groupchat", Remote: msg.Channel + "@" + b.Config.Muc, Text: sanitized}
	chat := xmpp.Chat{Type: "groupchat", Remote: msg.Channel + "@" + b.Config.Muc, Text: xmppHtml}
	client.SendRaw(chat)
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

func parseChannelNick(s string) (string, string) {
	var channelName, nick string
	parts := strings.Split(s, "@")
	if len(parts) >= 2 {
		channelName = parts[0]
	}
	parts = strings.Split(parts[1], "/")
	if len(parts) == 2 {
		nick = parts[1]
	}
	return channelName, nick
}

func (b *Bxmpp) handleXmpp() error {
	done := b.xmppKeepAlive(b.xc)
	defer close(done)
	nodelay := time.Time{}
	for {
		m, err := b.xc.Recv()
		flog.Debugf("le woop! %#v %#v", m, err)
		if err != nil {
			return err
		}
		switch v := m.(type) {
		case xmpp.Chat:
			flog.Debugf("RECEIVE: %#v", v)
			if v.Type == "groupchat" {
				channelName, nick := parseChannelNick(v.Remote)

				// If we haven't joined the channel, bail out!
				var channel *Channel
				var ok bool
				if channel, ok = b.Channels[channelName]; !ok {
					flog.Errorf("Got Message but we aren't in the channel! [%s]", channelName)
					return errors.New("Got Message from bad channel")
				}
				flog.Debugf("Current channel %#v", channel)

				if nick != b.Config.Nick && channel.XmppToMM[nick] == "" && v.Stamp == nodelay && v.Text != "" {
					flog.Debugf("Sending message from %s on %s to gateway", nick, b.Account)
					b.Remote <- config.Message{Username: nick, Text: v.Text, Channel: channelName, Account: b.Account, UserID: v.Remote}
				}
			}
		case xmpp.Presence:
			flog.Debugf("presence!")
			flog.Debugf("%#v", v)
			flog.Debugf("--- %s, %s, %s, %s, %s---", v.From, v.To, v.Type, v.Show, v.Status)
			status := true
			if v.Type == "unavailable" {
				status = false
			}
			channelName, nick := parseChannelNick(v.From)

			// If we haven't joined the channel, bail out!
			var channel *Channel
			var ok bool
			if channel, ok = b.Channels[channelName]; !ok {
				flog.Errorf("Got Precense but we aren't in the channel! [%s]", channelName)
				break
			}
			channel.Users[nick] = status
			flog.Debugf("Setting [%s].Users[%s]=%v", channelName, nick, status)
			flog.Debugf("%v", channel.Users)
		}
	}
}
