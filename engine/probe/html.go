package probe

import (
	"html"
	"regexp"
	"strings"
)

var htmlAttributes = regexp.MustCompile(`([^\s=/'"<>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?`)

type htmlTag struct {
	name  string
	attrs map[string]string
}

// pageTags conservatively reads attributes while skipping comments and raw text.
func pageTags(body string) []htmlTag {
	var tags []htmlTag
	ascii := []byte(body)
	for i, c := range ascii {
		if c >= 'A' && c <= 'Z' {
			ascii[i] = c + ('a' - 'A')
		}
	}
	lower := string(ascii)
	for pos := 0; pos < len(body); {
		offset := strings.IndexByte(body[pos:], '<')
		if offset < 0 {
			break
		}
		pos += offset
		if strings.HasPrefix(body[pos:], "<!--") {
			end := strings.Index(body[pos+4:], "-->")
			if end < 0 {
				break
			}
			pos += 4 + end + 3
			continue
		}
		start := pos + 1
		end := start
		var quote byte
		for ; end < len(body); end++ {
			c := body[end]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				continue
			}
			if c == '>' {
				break
			}
		}
		if end == len(body) {
			break
		}
		pos = end + 1
		nameEnd := start
		for nameEnd < end && ((lower[nameEnd] >= 'a' && lower[nameEnd] <= 'z') || (lower[nameEnd] >= '0' && lower[nameEnd] <= '9') || lower[nameEnd] == '-' || lower[nameEnd] == ':') {
			nameEnd++
		}
		if nameEnd == start {
			continue
		}
		name := lower[start:nameEnd]
		switch name {
		case "script", "style", "textarea", "title", "xmp", "iframe":
			close := strings.Index(lower[pos:], "</"+name)
			if close < 0 {
				return tags
			}
			pos += close
			continue
		}
		tag := htmlTag{name: name, attrs: map[string]string{}}
		for _, attr := range htmlAttributes.FindAllStringSubmatch(body[nameEnd:end], -1) {
			key := strings.ToLower(attr[1])
			if _, exists := tag.attrs[key]; exists {
				continue
			}
			tag.attrs[key] = html.UnescapeString(attr[2] + attr[3] + attr[4])
		}
		tags = append(tags, tag)
	}
	return tags
}
