package asciinema

import (
	"encoding/json"
	"io"
	"time"
)

// asciinema 官方目前只支持 o 和 i，目前 size 还未支持，只有 o 就足够了
const V2Version = 2
const V2OutputEvent = "o"
//const V2InputEvent = "i"
//const V2SizeEvent = "size"

// theme 用处不大
//type CastV2Theme struct {
//	Fg string `json:"fg"`
//	Bg string `json:"bg"`
//	Palette string `json:"palette"`
//}

type CastV2Header struct {
	Version uint `json:"version"`
	Width int `json:"width"`
	Height int `json:"height"`
	Timestamp int64 `json:"timestamp,omitempty"`
	Duration float32 `json:"duration,omitempty"`
	Title string  `json:"title,omitempty"`
	Command string  `json:"command,omitempty"`
	Env *map[string]string `json:"env,omitempty"`
	//Theme *CastV2Theme `json:"theme,omitempty"`
	IdleTimeLimit float32 `json:"idle_time_limit,omitempty"`
	outputStream *json.Encoder
}

type CastMetadata struct {
	Version   uint
	Width     int
	Height    int
	Title     string
	Timestamp time.Time
	Duration  float32
	Command   string
	Env       map[string]string
	IdleTimeLimit float32
}

func NewCastV2(meta *CastMetadata, fd io.Writer) (*CastV2Header, error) {
	var c CastV2Header
	c.Version = meta.Version
	c.Width = meta.Width
	c.Height = meta.Height
	if meta.Title != "" {
		c.Title = meta.Title
	}

	if meta.Timestamp.Unix() > 0 {
		c.Timestamp = meta.Timestamp.Unix()
	}

	if meta.Duration > 0.0 {
		c.Duration = meta.Duration
	}

	if meta.Command != "" {
		c.Command = meta.Command
	}

	if meta.Env != nil {
		c.Env = &meta.Env
	}

	if meta.IdleTimeLimit > 0.0 {
		c.IdleTimeLimit = meta.IdleTimeLimit
	}

	c.outputStream = json.NewEncoder(fd)
	return &c, nil
}

func (c *CastV2Header) PushHeader() error {
	return c.outputStream.Encode(c)
}

func (c *CastV2Header) PushData(start time.Time, ts time.Time, event string, data []byte) error {
	out := make([]interface{}, 3)
	out[0] = ts.Sub(start).Seconds()
	out[1] = event
	out[2] = string(data)
	// 使用这种方法能避免 \u001b 被写成 \x1b 导致 asciinema 回放错误
	return c.outputStream.Encode(out)
}