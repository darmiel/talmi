package configvet

import "sort"

// suggest returns up to 3 candidate names closest to target (small edit
// distance), closest first, for "did you mean" hints.
func suggest(target string, candidates []string) []string {
	type scored struct {
		name string
		dist int
	}
	limit := max(2, len(target)/3+1)
	var hits []scored
	for _, c := range candidates {
		if c == "" || c == target {
			continue
		}
		if d := levenshtein(target, c); d <= limit {
			hits = append(hits, scored{c, d})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].dist < hits[j].dist })
	out := make([]string, 0, len(hits))
	for i, h := range hits {
		if i == 3 {
			break
		}
		out = append(out, h.name)
	}
	return out
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, min(cur[j-1]+1, prev[j-1]+cost))
		}
		prev = cur
	}
	return prev[len(rb)]
}
