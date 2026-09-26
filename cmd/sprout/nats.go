package main

import (
	"bytes"
	"encoding/json"
	"runtime"

	log "github.com/yogzblr/imas/internal/log"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/ingredients/test"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/shell"

	nats "github.com/nats-io/nats.go"
)

func init() {
	createConfigRoot()
	pki.SetupPKISprout()
}

func natsInit(nc *nats.Conn) error {
	log.Debugf("Announcing on Farmer...")
	startup := config.Startup{}
	startup.Version.Arch = runtime.GOARCH
	startup.Version.Compiler = runtime.Version()
	startup.Version.GitCommit = GitCommit
	startup.Version.Tag = Tag
	startup.SproutID = sproutID
	startupEvent := "imas.sprouts.announce." + sproutID
	b, _ := json.Marshal(startup)
	err := nc.Publish(startupEvent, b)
	if err != nil {
		return err
	}
	if err = nc.LastError(); err != nil {
		log.Fatal(err)
	} else {
		log.Tracef("Successfully published startup message on `%s`.", startupEvent)
	}

	// Publish system facts on startup.
	sysFacts := facts.Collect()
	sysFacts.SproutID = sproutID
	factsB, _ := json.Marshal(sysFacts)
	if pubErr := nc.Publish("imas.sprouts."+sproutID+".facts", factsB); pubErr != nil {
		log.Errorf("failed to publish system facts: %v", pubErr)
	}

	// Respond to on-demand facts requests from the farmer.
	_, err = nc.Subscribe("imas.sprouts."+sproutID+".facts.request", func(m *nats.Msg) {
		fresh := facts.Collect()
		fresh.SproutID = sproutID
		b, _ := json.Marshal(fresh)
		m.Respond(b)
	})
	if err != nil {
		return err
	}

	_, err = nc.Subscribe("imas.sprouts."+sproutID+".cmd.run", func(m *nats.Msg) {
		var cmdRun apitypes.CmdRun
		json.NewDecoder(bytes.NewBuffer(m.Data)).Decode(&cmdRun)
		log.Trace(cmdRun)
		results, err := cmd.SRun(cmdRun)
		if err != nil {
			log.Error(err)
		}
		resultsB, err := json.Marshal(results)
		if err != nil {
			log.Error(err)
		}
		m.Respond(resultsB)
	})
	if err != nil {
		return err
	}
	_, err = nc.Subscribe("imas.sprouts."+sproutID+".test.ping", func(m *nats.Msg) {
		var ping apitypes.PingPong
		json.NewDecoder(bytes.NewBuffer(m.Data)).Decode(&ping)
		log.Trace(ping)
		pong, _ := test.SPing(ping)
		pongB, _ := json.Marshal(pong)
		m.Respond(pongB)
	})
	if err != nil {
		return err
	}
	_, err = nc.Subscribe("imas.sprouts."+sproutID+".cook", func(m *nats.Msg) {
		var rEnvelope cook.RecipeEnvelope
		json.NewDecoder(bytes.NewBuffer(m.Data)).Decode(&rEnvelope)
		log.Trace(rEnvelope)
		ackB, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: rEnvelope.JobID})
		m.Respond(ackB)
		go func() {
			if cookErr := cook.CookRecipeEnvelope(rEnvelope); cookErr != nil {
				log.Error(cookErr)
			}
		}()
	})
	if err != nil {
		return err
	}

	// Interactive shell sessions.
	_, err = nc.Subscribe("imas.sprouts."+sproutID+".shell.start", func(m *nats.Msg) {
		shell.HandleShellStart(nc, m)
	})
	if err != nil {
		return err
	}

	return nil
}
