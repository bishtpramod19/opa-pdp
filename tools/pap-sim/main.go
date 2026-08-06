// pap-sim is a local-only testing tool. It is NOT part of the ONAP policy-opa-pdp
// product code. It exists purely so a developer can simulate PAP sending real,
// correctly-structured PDP_UPDATE messages over Kafka, without hand-typing
// Base64 JSON payloads.
//
// It deliberately reuses the REAL structs (policy-opa-pdp/pkg/model) and the
// REAL Kafka producer wrapper (policy-opa-pdp/pkg/kafkacomm) from this repo,
// so every message it sends is guaranteed to match what the actual PdpUpdate
// struct/json.Marshal would produce - no manually-typed JSON to get wrong.
//
// Run:
//
//	KAFKA_URL=localhost:9092 PAP_TOPIC=policy-pdp-pap go run ./tools/pap-sim
//
// Then:
//
//	curl -X POST http://localhost:9999/deploy -H "Content-Type: application/json" -d '{
//	  "pdpName": "opa-xxxxxxxx-xxxx-...",
//	  "policyName": "blacklist",
//	  "regoPath": "test/policies/blacklist/policy.rego",
//	  "dataPath": "test/data/blacklist/data.json",
//	  "pdpSubgroup": "opaSubgroup"
//	}'
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/google/uuid"

	"policy-opa-pdp/pkg/kafkacomm"
	"policy-opa-pdp/pkg/model"
)

// inboundStatus is a minimal, local view of an incoming message - deliberately
// separate from model.PdpStatus so we don't have to worry about PdpMessageType's
// custom (int-backed) JSON marshaling on the read side. We only need three
// fields to detect "this is an unacknowledged registration heartbeat".
type inboundStatus struct {
	MessageType string  `json:"messageName"`
	Name        string  `json:"name"`
	PdpSubgroup *string `json:"pdpSubgroup"` // nil/absent == registration, per pdp-heartbeat.go
}

var (
	ackMu        sync.Mutex
	acknowledged = map[string]bool{} // pdpName -> already sent PDP_STATE_CHANGE(ACTIVE)
)

type deployRequest struct {
	PdpName     string `json:"pdpName"`     // must match the target OPA-PDP's current pdpattributes.PdpName
	PolicyName  string `json:"policyName"`  // e.g. "blacklist" - becomes the TOSCA policy-id AND the Rego package name
	RegoPath    string `json:"regoPath"`    // path to a .rego file on disk, relative to repo root
	DataPath    string `json:"dataPath"`    // path to a .json data file on disk, relative to repo root
	PdpSubgroup string `json:"pdpSubgroup"` // optional, defaults to "opaSubgroup"
}

type undeployRequest struct {
	PdpName       string `json:"pdpName"`
	PolicyName    string `json:"policyName"`    // e.g. "blacklist" - matches model.ToscaConceptIdentifier.Name
	PolicyVersion string `json:"policyVersion"` // e.g. "1.0.0"
	PdpSubgroup   string `json:"pdpSubgroup"`   // optional, defaults to "opaSubgroup"
}

func main() {
	topic := os.Getenv("PAP_TOPIC")
	if topic == "" {
		topic = "policy-pdp-pap"
	}
	listenAddr := os.Getenv("PAP_SIM_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":9999"
	}

	// GetKafkaProducer's bootstrapServers arg is unused by the real
	// implementation - it reads cfg.BootstrapServer (env KAFKA_URL) instead.
	// Passing "" here to be explicit that this argument is a no-op.
	producer, err := kafkacomm.GetKafkaProducer("", topic)
	if err != nil {
		log.Fatalf("failed to create Kafka producer: %v", err)
	}
	defer producer.Close()

	// A dedicated, unique consumer group so pap-sim gets its own full copy of
	// every message on the topic - same broadcast behavior every OPA-PDP
	// instance relies on, not a load-balanced share of it.
	consumerGroup := "pap-sim-" + uuid.New().String()
	consumer, err := kafkacomm.NewKafkaConsumer(topic, consumerGroup)
	if err != nil {
		log.Fatalf("failed to create Kafka consumer: %v", err)
	}
	go watchForRegistrations(consumer, producer, topic)

	http.HandleFunc("/deploy", func(w http.ResponseWriter, r *http.Request) {
		handleDeploy(w, r, producer, topic)
	})
	http.HandleFunc("/undeploy", func(w http.ResponseWriter, r *http.Request) {
		handleUndeploy(w, r, producer, topic)
	})

	log.Printf("pap-sim listening on %s, publishing to topic %q", listenAddr, topic)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func handleDeploy(w http.ResponseWriter, r *http.Request, producer *kafkacomm.KafkaProducer, topic string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req deployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PdpName == "" || req.PolicyName == "" || req.RegoPath == "" || req.DataPath == "" {
		http.Error(w, "pdpName, policyName, regoPath, dataPath are all required", http.StatusBadRequest)
		return
	}
	if req.PdpSubgroup == "" {
		req.PdpSubgroup = "opaSubgroup"
	}

	regoBytes, err := os.ReadFile(req.RegoPath)
	if err != nil {
		http.Error(w, "failed to read regoPath: "+err.Error(), http.StatusBadRequest)
		return
	}
	dataBytes, err := os.ReadFile(req.DataPath)
	if err != nil {
		http.Error(w, "failed to read dataPath: "+err.Error(), http.StatusBadRequest)
		return
	}

	toscaPolicy := model.ToscaPolicy{
		Type:        "onap.policies.native.opa",
		TypeVersion: "1.0.0",
		Name:        req.PolicyName,
		Version:     "1.0.0",
		Metadata: model.Metadata{
			PolicyID:      req.PolicyName,
			PolicyVersion: "1.0.0",
		},
		Properties: model.PolicyProperties{
			Policy: map[string]string{
				req.PolicyName: base64.StdEncoding.EncodeToString(regoBytes),
			},
			Data: map[string]string{
				"node." + req.PolicyName: base64.StdEncoding.EncodeToString(dataBytes),
			},
		},
	}

	pdpUpdate := model.PdpUpdate{
		Source:                 "pap-sim",
		PdpHeartbeatIntervalMs: 60000,
		MessageType:            "PDP_UPDATE",
		PoliciesToBeDeployed:   []model.ToscaPolicy{toscaPolicy},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{},
		Name:                   req.PdpName, // direct-name targeting; bypasses group/subgroup broadcast rules
		TimestampMs:            time.Now().UnixMilli(),
		PdpGroup:               "opaGroup",
		PdpSubgroup:            req.PdpSubgroup,
		RequestId:              uuid.New().String(),
	}

	payload, err := json.Marshal(pdpUpdate)
	if err != nil {
		http.Error(w, "failed to marshal PdpUpdate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	kafkaMsg := &kafka.Message{Value: payload}
	if err := producer.Produce(kafkaMsg, nil); err != nil {
		http.Error(w, "failed to publish to Kafka: "+err.Error(), http.StatusInternalServerError)
		return
	}
	producer.Flush(2000)

	log.Printf("published PDP_UPDATE for policy %q -> pdp %q on topic %q", req.PolicyName, req.PdpName, topic)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func handleUndeploy(w http.ResponseWriter, r *http.Request, producer *kafkacomm.KafkaProducer, topic string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req undeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PdpName == "" || req.PolicyName == "" || req.PolicyVersion == "" {
		http.Error(w, "pdpName, policyName, policyVersion are all required", http.StatusBadRequest)
		return
	}
	if req.PdpSubgroup == "" {
		req.PdpSubgroup = "opaSubgroup"
	}

	pdpUpdate := model.PdpUpdate{
		Source:                 "pap-sim",
		PdpHeartbeatIntervalMs: 60000,
		MessageType:            "PDP_UPDATE",
		PoliciesToBeDeployed:   []model.ToscaPolicy{},
		PoliciesToBeUndeployed: []model.ToscaConceptIdentifier{
			{Name: req.PolicyName, Version: req.PolicyVersion},
		},
		Name:        req.PdpName,
		TimestampMs: time.Now().UnixMilli(),
		PdpGroup:    "opaGroup",
		PdpSubgroup: req.PdpSubgroup,
		RequestId:   uuid.New().String(),
	}

	payload, err := json.Marshal(pdpUpdate)
	if err != nil {
		http.Error(w, "failed to marshal PdpUpdate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	kafkaMsg := &kafka.Message{Value: payload}
	if err := producer.Produce(kafkaMsg, nil); err != nil {
		http.Error(w, "failed to publish to Kafka: "+err.Error(), http.StatusInternalServerError)
		return
	}
	producer.Flush(2000)

	log.Printf("published PDP_UPDATE (undeploy) for policy %q v%q -> pdp %q on topic %q", req.PolicyName, req.PolicyVersion, req.PdpName, topic)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// watchForRegistrations continuously reads the topic, looking for PDP_STATUS
// heartbeats with no pdpSubgroup set (the exact signal pdp-heartbeat.go uses
// to mean "registration"). The first time it sees a given pdp name in that
// state, it sends a PDP_STATE_CHANGE(ACTIVE) - mirroring what a real PAP does
// on first contact - and remembers the name so it won't re-send on every
// subsequent heartbeat.
func watchForRegistrations(consumer *kafkacomm.KafkaConsumer, producer *kafkacomm.KafkaProducer, topic string) {
	log.Printf("pap-sim watching topic %q for registration heartbeats...", topic)
	for {
		msg, err := kafkacomm.ReadKafkaMessages(consumer)
		if err != nil {
			// Mirrors the real PdpMessageHandler's tolerant loop: log and keep going.
			continue
		}
		if msg == nil {
			continue
		}

		var status inboundStatus
		if err := json.Unmarshal(msg, &status); err != nil {
			continue
		}
		if status.MessageType != "PDP_STATUS" || status.Name == "" {
			continue
		}
		if status.PdpSubgroup != nil && *status.PdpSubgroup != "" {
			continue // already has a subgroup assigned; not a registration heartbeat
		}

		ackMu.Lock()
		already := acknowledged[status.Name]
		if !already {
			acknowledged[status.Name] = true
		}
		ackMu.Unlock()

		if already {
			continue
		}

		log.Printf("registration heartbeat detected from pdp %q - sending PDP_STATE_CHANGE(ACTIVE)", status.Name)
		if err := sendStateChangeActive(producer, status.Name); err != nil {
			log.Printf("failed to acknowledge registration for %q: %v", status.Name, err)
			// Allow a retry on the next heartbeat instead of leaving it stuck unacknowledged.
			ackMu.Lock()
			delete(acknowledged, status.Name)
			ackMu.Unlock()
		}
	}
}

func sendStateChangeActive(producer *kafkacomm.KafkaProducer, pdpName string) error {
	stateChange := model.PdpStateChange{
		Source:      "pap-sim",
		State:       "ACTIVE",
		MessageType: "PDP_STATE_CHANGE",
		Name:        pdpName,
		TimestampMs: time.Now().UnixMilli(),
		PdpGroup:    "opaGroup",
		PdpSubgroup: "opaSubgroup",
		RequestId:   uuid.New().String(),
	}

	payload, err := json.Marshal(stateChange)
	if err != nil {
		return err
	}

	kafkaMsg := &kafka.Message{Value: payload}
	if err := producer.Produce(kafkaMsg, nil); err != nil {
		return err
	}
	producer.Flush(2000)
	log.Printf("sent PDP_STATE_CHANGE(ACTIVE) to pdp %q", pdpName)
	return nil
}
