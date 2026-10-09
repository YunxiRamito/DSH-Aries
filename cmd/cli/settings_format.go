package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const bytesPerGB int64 = 1024 * 1024 * 1024

// settingInputDefault returns a human-readable editing default. Byte settings
// use ten fixed decimal places in the edit prompt to preserve the exact byte
// value; the settings list itself stays compact at two decimal places.
func settingInputDefault(field settingInfo, raw json.RawMessage) string {
	if field.Kind == "integer" {
		n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return strings.TrimSpace(string(raw))
		}
		if byteSettingKeys[field.Key] {
			return formatBytesGBPrecision(n, 10)
		}
		return strconv.FormatInt(n, 10)
	}
	if field.Kind == "boolean" {
		var value bool
		if json.Unmarshal(raw, &value) == nil {
			return strconv.FormatBool(value)
		}
	}
	if field.Kind == "string" {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			return value
		}
	}
	var value any
	if json.Unmarshal(raw, &value) == nil && value != nil {
		return fmt.Sprint(value)
	}
	return strings.TrimSpace(string(raw))
}

func parseSettingInput(field settingInfo, value string) (json.RawMessage, error) {
	if field.Kind == "integer" && byteSettingKeys[field.Key] {
		bytes, err := parseGBBytes(value)
		if err != nil {
			return nil, errors.New("enter a non-negative GB value, for example 1.5")
		}
		return json.Marshal(bytes)
	}
	return typedSettingValue(field.Kind, value)
}

func parseGBBytes(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if strings.HasSuffix(strings.ToLower(value), "gb") {
		value = strings.TrimSpace(value[:len(value)-2])
	}
	if value == "" || strings.HasPrefix(value, "-") {
		return 0, errors.New("invalid GB value")
	}
	wholeText, fractionText, hasFraction := strings.Cut(value, ".")
	if wholeText == "" {
		wholeText = "0"
	}
	if hasFraction && (fractionText == "" || len(fractionText) > 10) {
		return 0, errors.New("invalid GB precision")
	}
	whole, err := strconv.ParseInt(wholeText, 10, 64)
	const maxInt64 = int64(^uint64(0) >> 1)
	if err != nil || whole < 0 || whole > maxInt64/bytesPerGB {
		return 0, errors.New("GB value overflows the byte setting")
	}

	var fractionBytes int64
	if hasFraction {
		fraction, parseErr := strconv.ParseInt(fractionText, 10, 64)
		if parseErr != nil {
			return 0, errors.New("invalid GB fraction")
		}
		denominator := int64(1)
		for range fractionText {
			denominator *= 10
		}
		// The product can exceed MaxInt64 at ten fractional digits, but it
		// remains below MaxUint64; use unsigned integer arithmetic so parsing
		// stays exact and avoids floating-point/scientific formatting.
		product := uint64(fraction) * uint64(bytesPerGB)
		fractionBytes = int64(product / uint64(denominator))
		if product%uint64(denominator)*2 >= uint64(denominator) {
			fractionBytes++
		}
	}
	wholeBytes := whole * bytesPerGB
	if wholeBytes > maxInt64-fractionBytes {
		return 0, errors.New("GB value overflows the byte setting")
	}
	return wholeBytes + fractionBytes, nil
}

func formatBytesGBPrecision(value int64, precision int) string {
	if value < 0 {
		return "—"
	}
	if precision < 0 {
		precision = 0
	}
	if precision > 10 {
		precision = 10
	}
	whole := value / bytesPerGB
	if precision == 0 {
		return strconv.FormatInt(whole, 10)
	}
	scale := int64(1)
	for i := 0; i < precision; i++ {
		scale *= 10
	}
	// Long division avoids overflowing value*scale at ten decimal places.
	remainder := value % bytesPerGB
	fraction := int64(0)
	for i := 0; i < precision; i++ {
		remainder *= 10
		fraction = fraction*10 + remainder/bytesPerGB
		remainder %= bytesPerGB
	}
	if remainder*2 >= bytesPerGB {
		fraction++
	}
	if fraction == scale {
		whole++
		fraction = 0
	}
	if fraction == 0 {
		return strconv.FormatInt(whole, 10)
	}
	decimal := fmt.Sprintf("%0*d", precision, fraction)
	decimal = strings.TrimRight(decimal, "0")
	return strconv.FormatInt(whole, 10) + "." + decimal
}
