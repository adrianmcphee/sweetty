package shell

import "strings"

// The parser turns a command line into chained statements, each a pipeline of
// stages. It is deliberately a small subset of bash: enough that piping,
// redirecting, command chaining, quoting, and leading VAR=val assignments all
// behave, so common loader one-liners and a careful operator are not tripped by
// a naive split. It does not aim to be a complete shell grammar.

type stage struct {
	args    []string
	assigns map[string]string // leading VAR=val for this stage
	outNull bool              // stdout redirected to /dev/null
	outFile string            // stdout redirected to this overlay path
	appendT bool              // >> rather than >
}

type statement struct {
	stages []stage
	chain  string // chain operator that FOLLOWS this statement: "&&", "||", ";", or ""
}

type token struct {
	val string
	op  bool // an operator token (; && || | > >> 2> 2>&1 &> <)
}

// tokenize splits a line into words and operators, honouring single and double
// quotes. Adjacent quoted and bare atoms join into one word.
func tokenize(line string) []token {
	var toks []token
	var cur strings.Builder
	has := false
	flush := func() {
		if has {
			toks = append(toks, token{val: cur.String()})
			cur.Reset()
			has = false
		}
	}
	i := 0
	for i < len(line) {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			flush()
			i++
		case c == '\n' || c == '\r':
			// A newline separates statements, the way a pasted multi-line script's
			// lines do; treat it like ';'. (Loaders send multi-line recon as one blob.)
			flush()
			toks = append(toks, token{val: ";", op: true})
			i++
		case c == '(' || c == ')':
			// Subshell grouping. The honeypot does not isolate a real subshell; it
			// runs the inner commands inline, so the parens are emitted as bare tokens
			// that parse() drops. (A $(...) is consumed whole by the case below.)
			flush()
			toks = append(toks, token{val: string(c)})
			i++
		case c == '\'':
			has = true
			j := i + 1
			for j < len(line) && line[j] != '\'' {
				cur.WriteByte(line[j])
				j++
			}
			i = j + 1
		case c == '"':
			has = true
			j := i + 1
			for j < len(line) && line[j] != '"' {
				cur.WriteByte(line[j])
				j++
			}
			i = j + 1
		case c == '|':
			flush()
			if i+1 < len(line) && line[i+1] == '|' {
				toks = append(toks, token{val: "||", op: true})
				i += 2
			} else {
				toks = append(toks, token{val: "|", op: true})
				i++
			}
		case c == '&':
			flush()
			if i+1 < len(line) && line[i+1] == '&' {
				toks = append(toks, token{val: "&&", op: true})
				i += 2
			} else if i+1 < len(line) && line[i+1] == '>' {
				toks = append(toks, token{val: "&>", op: true})
				i += 2
			} else {
				// background & is ignored as a word boundary
				i++
			}
		case c == ';':
			flush()
			toks = append(toks, token{val: ";", op: true})
			i++
		case c == '>':
			flush()
			if i+1 < len(line) && line[i+1] == '>' {
				toks = append(toks, token{val: ">>", op: true})
				i += 2
			} else {
				toks = append(toks, token{val: ">", op: true})
				i++
			}
		case c == '<':
			flush()
			toks = append(toks, token{val: "<", op: true})
			i++
		case c == '2' && i+2 < len(line) && line[i+1] == '>':
			// 2> or 2>&1
			flush()
			if i+3 < len(line) && line[i+1] == '>' && line[i+2] == '&' && line[i+3] == '1' {
				toks = append(toks, token{val: "2>&1", op: true})
				i += 4
			} else {
				toks = append(toks, token{val: "2>", op: true})
				i += 2
			}
		case c == '$' && i+1 < len(line) && line[i+1] == '(':
			// Keep a $(...) command substitution as one word, balancing nested
			// parens, so a space inside it does not split the token (e.g. the loader
			// idiom `ls -lh $(which ls)`). expand() evaluates it later.
			has = true
			cur.WriteByte('$')
			cur.WriteByte('(')
			depth := 1
			j := i + 2
			for j < len(line) && depth > 0 {
				switch line[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
				cur.WriteByte(line[j])
				j++
			}
			i = j
		case c == '`':
			// Likewise keep a `...` backtick substitution as one word.
			has = true
			cur.WriteByte('`')
			j := i + 1
			for j < len(line) && line[j] != '`' {
				cur.WriteByte(line[j])
				j++
			}
			if j < len(line) {
				cur.WriteByte('`')
				j++
			}
			i = j
		default:
			has = true
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return toks
}

// parse splits tokens into chained statements of pipeline stages, with leading
// assignments and redirects pulled out of each stage.
func parse(line string) []statement {
	toks := tokenize(line)
	var stmts []statement
	var cur statement
	var stg stage
	stg.assigns = map[string]string{}

	finishStage := func() {
		if len(stg.args) > 0 || len(stg.assigns) > 0 {
			cur.stages = append(cur.stages, stg)
		}
		stg = stage{assigns: map[string]string{}}
	}
	finishStmt := func(chain string) {
		finishStage()
		if len(cur.stages) > 0 {
			cur.chain = chain
			stmts = append(stmts, cur)
		}
		cur = statement{}
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if !t.op {
			// Grouping markers: the honeypot runs ( ) subshells and { } groups inline,
			// so the bare braces/parens are dropped rather than treated as a command.
			switch t.val {
			case "(", ")", "{", "}":
				continue
			}
			// leading assignment only while no args yet in this stage
			if len(stg.args) == 0 {
				if k, v, ok := splitAssign(t.val); ok {
					stg.assigns[k] = v
					continue
				}
			}
			stg.args = append(stg.args, t.val)
			continue
		}
		switch t.val {
		case "|":
			finishStage()
		case ";":
			finishStmt(";")
		case "&&":
			finishStmt("&&")
		case "||":
			finishStmt("||")
		case ">", ">>", "&>":
			if i+1 < len(toks) {
				target := toks[i+1].val
				i++
				if target == "/dev/null" {
					stg.outNull = true
				} else {
					stg.outFile = target
					stg.appendT = t.val == ">>"
				}
			}
		case "2>":
			if i+1 < len(toks) {
				i++ // swallow stderr target; honeypot output is on stdout
			}
		case "2>&1", "<":
			if t.val == "<" && i+1 < len(toks) {
				i++ // ignore input redirection target
			}
		}
	}
	finishStmt("")
	return stmts
}

func splitAssign(s string) (string, string, bool) {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return "", "", false
	}
	name := s[:eq]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')) {
			return "", "", false
		}
	}
	return name, s[eq+1:], true
}
