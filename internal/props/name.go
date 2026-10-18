package props

// MaxNameLen is farmer.props' name column width.
const MaxNameLen = 191

// ValidName reports whether name is plain ASCII from a small set: 1 to
// MaxNameLen letters, digits, '_', '-', '.' and ':'. farmer.props' name
// column takes the schema's default collation, which in PXC folds case and
// accents and ignores some control characters, so a name like "OS", "ös"
// or "o\x01s" can address the reserved "os" row. Restricting writable
// names (props.set, props.static) to this set leaves case as the only fold,
// which facts.IsReservedPropName handles.
func ValidName(name string) bool {
	if name == "" || len(name) > MaxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}
