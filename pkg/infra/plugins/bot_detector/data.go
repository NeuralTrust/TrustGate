package bot_detector

type BotDetectorData struct {
	Fingerprint interface{} `json:"fingerprint"`
	Action      string      `json:"action"` // e.g. "AlertOnly", "Throttle", "Block"
	BotScore    float64     `json:"bot_score"`
	Threshold   float64     `json:"threshold"`
}
