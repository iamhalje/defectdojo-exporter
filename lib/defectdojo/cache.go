package defectdojo

import "sync"

// productTypeCache stores mapping of product type ID -> name to avoid repeated
// API calls for the same product type. It is intentionally simple and unbounded
// since the cardinality is typically small.
var (
	productTypeCacheMu sync.RWMutex
	productTypeCache   = make(map[int]string)
)

func getCachedProductTypeName(productTypeID int) (string, bool) {
	productTypeCacheMu.RLock()
	name, ok := productTypeCache[productTypeID]
	productTypeCacheMu.RUnlock()
	return name, ok
}

func setCachedProductTypeName(productTypeID int, name string) {
	productTypeCacheMu.Lock()
	productTypeCache[productTypeID] = name
	productTypeCacheMu.Unlock()
}