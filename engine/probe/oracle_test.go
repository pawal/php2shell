package probe

import (
	"fmt"
	"strings"
	"testing"
)

// unpatchedPage is the shape of an unpatched answer with display_errors on.
const unpatchedPage = `<br />
<b>Warning</b>:  PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, &quot;-&quot;, and &quot;,&quot; characters are allowed in <b>Unknown</b> on line <b>0</b><br />
<br />
<b>Warning</b>:  PHP Request Startup: Failed to read session data: files (path: ) in <b>Unknown</b> on line <b>0</b><br />
<br />
<b>Warning</b>:  PHP Request Startup: Failed to write session data (files). Please verify that the current setting of session.save_path is correct () in <b>Unknown</b> on line <b>0</b><br />
`

func TestWarningLines(t *testing.T) {
	got := warningLines(strings.Repeat(unpatchedPage, 2) + "<p>Welcome</p>")
	if len(got) != 3 {
		t.Fatalf("got %d lines: %q", len(got), got)
	}
	if want := `Warning: PHP Request Startup: Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, "-", and "," characters are allowed in Unknown on line 0`; got[0] != want {
		t.Errorf("got %q, want %q", got[0], want)
	}
	if !strings.HasPrefix(got[2], "Warning: PHP Request Startup: Failed to write session data (files).") {
		t.Errorf("write line %q", got[2])
	}
	plain := warningLines("PHP Warning:  Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0\nok")
	if len(plain) != 1 || !strings.Contains(plain[0], "/var/lib/php/sessions") {
		t.Errorf("plain text: %q", plain)
	}
	var many strings.Builder
	for i := range 10 {
		fmt.Fprintf(&many, "Failed to read session data %d %s<br>", i, strings.Repeat("é", 400))
	}
	bounded := warningLines(many.String())
	if len(bounded) != maxWarningLines {
		t.Errorf("kept %d lines", len(bounded))
	}
	for _, line := range bounded {
		if len(line) > maxWarningLine || !strings.HasPrefix(line, "Failed to read") || strings.ContainsRune(line, '�') {
			t.Errorf("line not bounded cleanly: %d bytes", len(line))
		}
	}
	if warningLines("<p>Welcome</p>") != nil {
		t.Error("lines without warnings")
	}
}
