package murmurdb

const (
	maxCachedStatements = 128
	maxCachedBytes      = 8 << 20
)

// cacheRoom runs with c.mu held. Busy entries belong to open Rows and must
// never be evicted; a new statement remains caller-owned if no room exists.
func (c *conn) cacheRoom(bytes int) bool {
	if bytes > maxCachedBytes {
		return false
	}
	for len(c.cache) >= maxCachedStatements || c.cacheBytes+bytes > maxCachedBytes {
		var oldest string
		var candidate *cachedStmt
		for query, entry := range c.cache {
			if !entry.busy && (candidate == nil || entry.used < candidate.used) {
				oldest, candidate = query, entry
			}
		}
		if candidate == nil {
			return false
		}
		c.dropCached(oldest)
	}
	return true
}

func (c *conn) dropCached(query string) {
	if entry, ok := c.cache[query]; ok {
		entry.st.Close()
		c.cacheBytes -= entry.bytes
		delete(c.cache, query)
	}
}

func (c *conn) touchCached(entry *cachedStmt) {
	c.cacheTick++
	entry.used = c.cacheTick
}
