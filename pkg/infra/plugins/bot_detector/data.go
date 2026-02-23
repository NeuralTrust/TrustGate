package bot_detector

type BotDetectorData struct {
	Fingerprint interface{} `json:"fingerprint"`
	Action      string      `json:"action"` // e.g. "Observe", "Throttle", "Enforce"
	BotScore    float64     `json:"bot_score"`
	Threshold   float64     `json:"threshold"`
}
