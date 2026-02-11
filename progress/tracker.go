package progress

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"bptools/awsdata"
	"bptools/checker"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

type prefetchStartMsg struct{ total int }
type prefetchCompleteMsg struct {
	name string
	err  error
}
type prefetchDoneMsg struct {
	total    int
	failures int
}

type checkStartMsg struct{ total int }
type checkCompleteMsg struct {
	id       string
	findings int
	errors   int
}
type checkDoneMsg struct {
	total    int
	findings int
	errors   int
}

type resultsReadyMsg struct {
	results      []checker.Result
	descriptions map[string]string
}

type logLineMsg struct {
	level string
	line  string
}

type logEntry struct {
	level string
	line  string
}

type resultRow struct {
	kind    string
	status  checker.Status
	checkID string
	text    string
}

type trackerModel struct {
	width  int
	height int

	prefetchBar progress.Model
	rulesBar    progress.Model

	prefetchTotal int
	prefetchDone  int
	prefetchFail  int

	rulesTotal    int
	rulesDone     int
	rulesFindings int
	rulesErrors   int

	logLines        []logEntry
	showResults     bool
	resultRows      []resultRow
	resultOffset    int
	resultRuleCount int
	resultItemCount int
	resultErrCount  int
}

func newTrackerModel() trackerModel {
	bar := progress.New(progress.WithScaledGradient("#00AEEF", "#00D084"))
	return trackerModel{
		prefetchBar: bar,
		rulesBar:    bar,
		width:       80,
		height:      24,
	}
}

func (m trackerModel) Init() tea.Cmd { return nil }

func (m trackerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
		return m, nil
	case tea.KeyMsg:
		if v.String() == "q" || v.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.showResults {
			viewportRows := m.resultViewportRows()
			maxOffset := 0
			if len(m.resultRows) > viewportRows {
				maxOffset = len(m.resultRows) - viewportRows
			}
			switch v.String() {
			case "down", "j":
				if m.resultOffset < maxOffset {
					m.resultOffset++
				}
			case "up", "k":
				if m.resultOffset > 0 {
					m.resultOffset--
				}
			case "pgdown":
				m.resultOffset += viewportRows
				if m.resultOffset > maxOffset {
					m.resultOffset = maxOffset
				}
			case "pgup":
				m.resultOffset -= viewportRows
				if m.resultOffset < 0 {
					m.resultOffset = 0
				}
			case "g":
				m.resultOffset = 0
			case "G":
				m.resultOffset = maxOffset
			}
		}
		return m, nil
	case prefetchStartMsg:
		m.prefetchTotal = v.total
		m.prefetchDone = 0
		m.prefetchFail = 0
		m.appendLog(fmt.Sprintf("prefetch start: %d caches", v.total))
		return m, nil
	case prefetchCompleteMsg:
		if m.prefetchDone < m.prefetchTotal {
			m.prefetchDone++
		}
		if v.err != nil {
			m.prefetchFail++
			m.appendLogLevel("error", fmt.Sprintf("prefetch error: %s: %v", v.name, v.err))
		} else {
			m.appendLogLevel("success", fmt.Sprintf("prefetch ok: %s", v.name))
		}
		return m, nil
	case prefetchDoneMsg:
		m.prefetchTotal = v.total
		m.prefetchDone = v.total
		m.prefetchFail = v.failures
		if v.failures > 0 {
			m.appendLog(fmt.Sprintf("prefetch done with %d failures", v.failures))
		} else {
			m.appendLog("prefetch done")
		}
		return m, nil
	case checkStartMsg:
		m.rulesTotal = v.total
		m.rulesDone = 0
		m.rulesFindings = 0
		m.rulesErrors = 0
		m.appendLog(fmt.Sprintf("rule checks start: %d", v.total))
		return m, nil
	case checkCompleteMsg:
		if m.rulesDone < m.rulesTotal {
			m.rulesDone++
		}
		m.rulesFindings += v.findings
		m.rulesErrors += v.errors
		if v.errors > 0 {
			m.appendLogLevel("warn", fmt.Sprintf("rule check warning: %s (findings=%d errors=%d)", v.id, v.findings, v.errors))
		} else {
			m.appendLogLevel("success", fmt.Sprintf("rule check ok: %s (findings=%d)", v.id, v.findings))
		}
		return m, nil
	case checkDoneMsg:
		m.rulesTotal = v.total
		m.rulesDone = v.total
		m.rulesFindings = v.findings
		m.rulesErrors = v.errors
		m.appendLog(fmt.Sprintf("rule checks done: checks=%d findings=%d errors=%d", v.total, v.findings, v.errors))
		return m, nil
	case resultsReadyMsg:
		m.showResults = true
		m.resultRows, m.resultRuleCount, m.resultItemCount, m.resultErrCount = buildResultRows(v.results, v.descriptions)
		m.resultOffset = 0
		return m, nil
	case logLineMsg:
		m.appendLogLevel(v.level, v.line)
		return m, nil
	}
	return m, nil
}

func (m trackerModel) View() string {
	if m.showResults {
		return m.viewResults()
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Padding(0, 1)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	tsStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	infoBadgeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(lipgloss.Color("238")).Bold(true).Padding(0, 1)
	successBadgeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Background(lipgloss.Color("236")).Bold(true).Padding(0, 1)
	warnBadgeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Background(lipgloss.Color("236")).Bold(true).Padding(0, 1)
	errorBadgeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Background(lipgloss.Color("236")).Bold(true).Padding(0, 1)
	panelStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("238")).
		Padding(0, 1)

	bodyWidth := m.width - 4
	if bodyWidth < 40 {
		bodyWidth = 40
	}

	prefetchPct := ratio(m.prefetchDone, m.prefetchTotal)
	rulesPct := ratio(m.rulesDone, m.rulesTotal)

	prefetchLabel := labelStyle.Render("API prefetch")
	prefetchCount := fmt.Sprintf("%d/%d", m.prefetchDone, m.prefetchTotal)
	prefetchStatus := ""
	if m.prefetchFail > 0 {
		prefetchStatus = warnStyle.Render(fmt.Sprintf("failures=%d", m.prefetchFail))
	} else if m.prefetchDone > 0 && m.prefetchDone == m.prefetchTotal {
		prefetchStatus = okStyle.Render("ok")
	}

	prefetchExtraWidth := lipgloss.Width(prefetchLabel) + 1 + lipgloss.Width(prefetchCount)
	if prefetchStatus != "" {
		prefetchExtraWidth += 1 + lipgloss.Width(prefetchStatus)
	}
	prefetchBarWidth := bodyWidth - prefetchExtraWidth - 1
	if prefetchBarWidth < 8 {
		prefetchBarWidth = 8
	}
	m.prefetchBar.Width = prefetchBarWidth

	prefetchLine := fmt.Sprintf("%s %s %s", prefetchLabel, m.prefetchBar.ViewAs(prefetchPct), prefetchCount)
	if prefetchStatus != "" {
		prefetchLine += " " + prefetchStatus
	}

	rulesBarWidth := bodyWidth - 28
	if rulesBarWidth < 20 {
		rulesBarWidth = 20
	}
	m.rulesBar.Width = rulesBarWidth

	ruleLine := fmt.Sprintf(
		"%s   %s %d/%d",
		labelStyle.Render("Rule checks"),
		m.rulesBar.ViewAs(rulesPct),
		m.rulesDone,
		m.rulesTotal,
	)
	if m.rulesDone > 0 {
		ruleLine += " " + labelStyle.Render(fmt.Sprintf("findings=%d errors=%d", m.rulesFindings, m.rulesErrors))
	}

	statusPanel := panelStyle.Width(bodyWidth).Render(lipgloss.JoinVertical(
		lipgloss.Left,
		titleStyle.Render("bptools progress"),
		prefetchLine,
		ruleLine,
	))

	logPanelHeight := m.height - 10
	if logPanelHeight < 6 {
		logPanelHeight = 6
	}
	logContentWidth := bodyWidth - 4
	if logContentWidth < 10 {
		logContentWidth = 10
	}
	logEntries := m.tailLogs(logPanelHeight - 2)
	logLines := make([]string, 0, len(logEntries))
	for _, entry := range logEntries {
		badgeStyle := infoBadgeStyle
		badge := "INFO"
		switch entry.level {
		case "success":
			badgeStyle = successBadgeStyle
			badge = "OK"
		case "warn":
			badgeStyle = warnBadgeStyle
			badge = "WARN"
		case "error":
			badgeStyle = errorBadgeStyle
			badge = "ERR"
		}
		logLines = append(logLines, renderEventLine(tsStyle, badgeStyle, badge, entry.line, logContentWidth))
	}
	if len(logLines) == 0 {
		logLines = []string{labelStyle.Render("No events yet")}
	}

	logPanel := panelStyle.Width(bodyWidth).Height(logPanelHeight).Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			titleStyle.Render("Events"),
			lipgloss.JoinVertical(lipgloss.Left, logLines...),
		),
	)

	footer := labelStyle.Render("Press q to quit")
	if m.prefetchDone == m.prefetchTotal && m.rulesDone == m.rulesTotal && m.rulesTotal > 0 {
		footer = okStyle.Render("Completed") + " " + labelStyle.Render("Press q to quit")
	} else if m.prefetchFail > 0 || m.rulesErrors > 0 {
		footer = warnStyle.Render("Warnings detected") + " " + labelStyle.Render("Press q to quit")
	}

	return lipgloss.NewStyle().Padding(1, 1).Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			statusPanel,
			logPanel,
			footer,
		),
	)
}

func (m trackerModel) viewResults() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Padding(0, 1)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("111"))
	panelStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("238")).
		Padding(0, 1)
	failBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Background(lipgloss.Color("236")).Bold(true).Padding(0, 1)
	errBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Background(lipgloss.Color("236")).Bold(true).Padding(0, 1)

	bodyWidth := m.width - 4
	if bodyWidth < 40 {
		bodyWidth = 40
	}

	summaryText := fmt.Sprintf("rules_with_issues=%d findings=%d", m.resultRuleCount, m.resultItemCount)
	if m.resultErrCount > 0 {
		summaryText += fmt.Sprintf(" errors=%d", m.resultErrCount)
	}
	summaryPanel := panelStyle.Width(bodyWidth).Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			titleStyle.Render("bptools results"),
			labelStyle.Render(summaryText),
		),
	)

	panelHeight := m.height - 8
	if panelHeight < 8 {
		panelHeight = 8
	}
	contentWidth := bodyWidth - 4
	if contentWidth < 10 {
		contentWidth = 10
	}
	viewportRows := m.resultViewportRows()
	maxOffset := 0
	if len(m.resultRows) > viewportRows {
		maxOffset = len(m.resultRows) - viewportRows
	}
	if m.resultOffset > maxOffset {
		m.resultOffset = maxOffset
	}

	lines := make([]string, 0, viewportRows)
	if len(m.resultRows) == 0 {
		lines = append(lines, okStyle.Render("No non-compliant resources found."))
	} else {
		start := m.resultOffset
		end := start + viewportRows
		if end > len(m.resultRows) {
			end = len(m.resultRows)
		}
		for _, row := range m.resultRows[start:end] {
			if row.kind == "header" {
				lines = append(lines, headerStyle.Render(truncateDisplayWidth(row.text, contentWidth)))
				continue
			}
			if row.kind == "meta" {
				lines = append(lines, labelStyle.Render(truncateDisplayWidth(row.text, contentWidth)))
				continue
			}

			badge := failBadge.Render("FAIL")
			if row.status == checker.StatusError {
				badge = errBadge.Render("ERR")
			}
			prefixWidth := lipgloss.Width(badge) + 1
			lines = append(lines, badge+" "+truncateDisplayWidth(row.text, contentWidth-prefixWidth))
		}
	}

	resultPanel := panelStyle.Width(bodyWidth).Height(panelHeight).Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			titleStyle.Render("Non-compliant Findings"),
			lipgloss.JoinVertical(lipgloss.Left, lines...),
		),
	)

	scrollHint := labelStyle.Render("j/k or ↑/↓ scroll • g/G top/bottom • q quit")
	if len(m.resultRows) <= viewportRows {
		scrollHint = labelStyle.Render("q quit")
	} else {
		scrollHint = labelStyle.Render(fmt.Sprintf(
			"j/k or ↑/↓ scroll • g/G top/bottom • q quit (%d-%d/%d)",
			m.resultOffset+1,
			minInt(m.resultOffset+viewportRows, len(m.resultRows)),
			len(m.resultRows),
		))
	}

	if m.resultErrCount > 0 {
		scrollHint = errStyle.Render("Errors detected") + " " + scrollHint
	} else if m.resultItemCount > 0 {
		scrollHint = warnStyle.Render("Non-compliant resources found") + " " + scrollHint
	}

	return lipgloss.NewStyle().Padding(1, 1).Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			summaryPanel,
			resultPanel,
			scrollHint,
		),
	)
}

func buildResultRows(results []checker.Result, descriptions map[string]string) ([]resultRow, int, int, int) {
	grouped := make(map[string][]checker.Result)
	errorCount := 0
	for _, r := range results {
		if r.Status != checker.StatusFail && r.Status != checker.StatusError {
			continue
		}
		grouped[r.CheckID] = append(grouped[r.CheckID], r)
		if r.Status == checker.StatusError {
			errorCount++
		}
	}

	if len(grouped) == 0 {
		return nil, 0, 0, 0
	}

	checkIDs := make([]string, 0, len(grouped))
	for checkID := range grouped {
		checkIDs = append(checkIDs, checkID)
	}
	sort.Strings(checkIDs)

	rows := make([]resultRow, 0, len(results))
	itemCount := 0
	for _, checkID := range checkIDs {
		items := grouped[checkID]
		sort.Slice(items, func(i, j int) bool {
			if items[i].Status != items[j].Status {
				return items[i].Status < items[j].Status
			}
			if items[i].ResourceID != items[j].ResourceID {
				return items[i].ResourceID < items[j].ResourceID
			}
			return items[i].Message < items[j].Message
		})

		failCount := 0
		errCount := 0
		for _, item := range items {
			if item.Status == checker.StatusError {
				errCount++
			} else {
				failCount++
			}
		}

		header := fmt.Sprintf("%s (fail=%d error=%d)", checkID, failCount, errCount)
		headerStatus := checker.StatusFail
		if errCount > 0 {
			headerStatus = checker.StatusError
		}
		rows = append(rows, resultRow{
			kind:    "header",
			status:  headerStatus,
			checkID: checkID,
			text:    header,
		})
		if desc := strings.TrimSpace(descriptions[checkID]); desc != "" {
			rows = append(rows, resultRow{
				kind:    "meta",
				checkID: checkID,
				text:    fmt.Sprintf("description: %s", desc),
			})
		}
		rows = append(rows, resultRow{
			kind:    "meta",
			checkID: checkID,
			text:    fmt.Sprintf("docs: https://docs.aws.amazon.com/config/latest/developerguide/%s.html", checkID),
		})

		for _, item := range items {
			resource := strings.TrimSpace(item.ResourceID)
			if resource == "" {
				resource = "<account>"
			}
			msg := strings.TrimSpace(item.Message)
			if msg == "" {
				msg = "-"
			}
			rows = append(rows, resultRow{
				kind:    "detail",
				status:  item.Status,
				checkID: checkID,
				text:    fmt.Sprintf("%s — %s", resource, msg),
			})
			itemCount++
		}
	}

	return rows, len(checkIDs), itemCount, errorCount
}

func (m trackerModel) resultViewportRows() int {
	panelHeight := m.height - 8
	if panelHeight < 8 {
		panelHeight = 8
	}
	rows := panelHeight - 2
	if rows < 3 {
		rows = 3
	}
	return rows
}

func ratio(done, total int) float64 {
	if total <= 0 {
		return 0
	}
	if done >= total {
		return 1
	}
	if done <= 0 {
		return 0
	}
	return float64(done) / float64(total)
}

func (m *trackerModel) appendLog(line string) {
	m.appendLogLevel("info", line)
}

func (m *trackerModel) appendLogLevel(level string, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if level == "" {
		level = "info"
	}
	m.logLines = append(m.logLines, logEntry{level: level, line: line})
	if len(m.logLines) > 500 {
		m.logLines = m.logLines[len(m.logLines)-500:]
	}
}

func (m trackerModel) tailLogs(maxLines int) []logEntry {
	if maxLines <= 0 || len(m.logLines) == 0 {
		return nil
	}
	start := len(m.logLines) - maxLines
	if start < 0 {
		start = 0
	}
	selected := m.logLines[start:]
	out := make([]logEntry, 0, len(selected))
	for _, entry := range selected {
		out = append(out, logEntry{level: entry.level, line: entry.line})
	}
	return out
}

func splitTimestamp(line string) (string, string) {
	if len(line) >= 11 && line[0] == '[' && line[9] == ']' && line[10] == ' ' {
		return line[:10], line[11:]
	}
	return "", line
}

func renderEventLine(tsStyle lipgloss.Style, badgeStyle lipgloss.Style, badge string, line string, maxWidth int) string {
	ts, msg := splitTimestamp(line)
	badgePart := badgeStyle.Render(badge)
	if ts == "" {
		prefixWidth := lipgloss.Width(badgePart) + 1
		return badgePart + " " + truncateDisplayWidth(msg, maxWidth-prefixWidth)
	}
	tsPart := tsStyle.Render(ts)
	prefixWidth := lipgloss.Width(tsPart) + 1 + lipgloss.Width(badgePart) + 1
	return tsPart + " " + badgePart + " " + truncateDisplayWidth(msg, maxWidth-prefixWidth)
}

func truncateDisplayWidth(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 {
		return ""
	}
	if runewidth.StringWidth(s) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	var b strings.Builder
	width := 0
	for _, r := range s {
		w := runewidth.RuneWidth(r)
		if width+w > max-1 {
			break
		}
		b.WriteRune(r)
		width += w
	}
	b.WriteRune('…')
	return b.String()
}

func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// Tracker coordinates progress updates between prefetch and rule runs.
type Tracker struct {
	prog   *tea.Program
	doneCh chan struct{}
	once   sync.Once
}

func New(out io.Writer) *Tracker {
	if out == nil {
		out = os.Stderr
	}
	model := newTrackerModel()
	program := tea.NewProgram(model, tea.WithOutput(out), tea.WithAltScreen())
	t := &Tracker{
		prog:   program,
		doneCh: make(chan struct{}),
	}

	go func() {
		_, _ = program.Run()
		close(t.doneCh)
	}()

	return t
}

func (t *Tracker) Wait() {
	if t == nil {
		return
	}
	<-t.doneCh
}

func (t *Tracker) Close() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.prog.Quit()
	})
}

func (t *Tracker) send(msg tea.Msg) {
	if t == nil || t.prog == nil {
		return
	}
	t.prog.Send(msg)
}

func (t *Tracker) eventf(level string, format string, args ...any) {
	ts := time.Now().Format("15:04:05")
	t.send(logLineMsg{
		level: level,
		line:  fmt.Sprintf("[%s] %s", ts, fmt.Sprintf(format, args...)),
	})
}

func (t *Tracker) ShowResults(results []checker.Result, descriptions map[string]string) {
	t.send(resultsReadyMsg{results: results, descriptions: descriptions})
}

func (t *Tracker) PrefetchHooks() awsdata.PrefetchHooks {
	return awsdata.PrefetchHooks{
		OnStart: func(total int) {
			t.eventf("info", "starting API prefetch (%d caches)", total)
			t.send(prefetchStartMsg{total: total})
		},
		OnComplete: func(name string, err error) {
			t.send(prefetchCompleteMsg{name: name, err: err})
		},
		OnDone: func(total int, failures int) {
			t.send(prefetchDoneMsg{total: total, failures: failures})
			if failures > 0 {
				t.eventf("warn", "prefetch completed with failures (%d/%d)", failures, total)
				return
			}
			t.eventf("success", "prefetch completed (%d/%d)", total, total)
		},
	}
}

func (t *Tracker) RunHooks() checker.RunHooks {
	return checker.RunHooks{
		OnStart: func(total int) {
			t.eventf("info", "starting rule checks (%d)", total)
			t.send(checkStartMsg{total: total})
		},
		OnComplete: func(id string, count int, errCount int) {
			t.send(checkCompleteMsg{id: id, findings: count, errors: errCount})
			if errCount > 0 {
				t.eventf("warn", "check had errors: %s (findings=%d errors=%d)", id, count, errCount)
			}
		},
		OnDone: func(total int, findings int, errors int) {
			t.send(checkDoneMsg{total: total, findings: findings, errors: errors})
			if errors > 0 {
				t.eventf("warn", "rule checks completed (checks=%d findings=%d errors=%d)", total, findings, errors)
				return
			}
			t.eventf("success", "rule checks completed (checks=%d findings=%d errors=%d)", total, findings, errors)
		},
	}
}
