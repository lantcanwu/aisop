package enricher

import (
	"net"
	"strings"
	"time"

	"cyberstrike-ai/internal/secops/models"
)

type GeoInfo struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
	ASN       string  `json:"asn"`
}

type ThreatIntelInfo struct {
	Source      string    `json:"source"`
	ThreatType  string    `json:"threat_type"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags"`
	Description string    `json:"description"`
}

type EnricherService struct {
	geoDatabase   map[string]*GeoInfo
	threatIntelDB map[string][]ThreatIntelInfo
}

func NewEnricherService() *EnricherService {
	return &EnricherService{
		geoDatabase:   make(map[string]*GeoInfo),
		threatIntelDB: make(map[string][]ThreatIntelInfo),
	}
}

func (s *EnricherService) EnrichEvent(event *models.SecurityEvent) {
	s.enrichIPLocations(event)
	s.enrichThreatIntel(event)
}

func (s *EnricherService) enrichIPLocations(event *models.SecurityEvent) {
	for i := range event.IoCs {
		ioc := &event.IoCs[i]
		if ioc.Type == models.IoCTypeIP {
			if geo := s.LookupGeo(ioc.Value); geo != nil {
				if event.RawData == nil {
					event.RawData = make(map[string]interface{})
				}
				event.RawData["geo"] = geo
			}
		}
	}
}

func (s *EnricherService) enrichThreatIntel(event *models.SecurityEvent) {
	for i := range event.IoCs {
		ioc := &event.IoCs[i]
		if intel := s.LookupThreatIntel(ioc.Value); intel != nil {
			ioc.Tags = append(ioc.Tags, intel.ThreatType)
			ioc.Confidence = intel.Confidence
		}
	}
}

func (s *EnricherService) LookupGeo(ip string) *GeoInfo {
	if geo, ok := s.geoDatabase[ip]; ok {
		return geo
	}

	geo := s.lookupGeoFromExternal(ip)
	if geo != nil {
		s.geoDatabase[ip] = geo
	}
	return geo
}

func (s *EnricherService) lookupGeoFromExternal(ip string) *GeoInfo {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	if parsedIP.IsPrivate() || parsedIP.IsLoopback() {
		return &GeoInfo{
			Country: "Reserved",
			Region:  "Reserved",
			City:    "Reserved",
		}
	}

	return &GeoInfo{
		Country:   "Unknown",
		Region:    "Unknown",
		City:      "Unknown",
		Latitude:  0,
		Longitude: 0,
		ISP:       "Unknown",
		ASN:       "Unknown",
	}
}

func (s *EnricherService) LookupThreatIntel(value string) *ThreatIntelInfo {
	value = strings.ToLower(value)

	if intelList, ok := s.threatIntelDB[value]; ok {
		if len(intelList) > 0 {
			return &intelList[0]
		}
	}

	return nil
}

func (s *EnricherService) AddThreatIntel(iocType models.IoCType, value string, info ThreatIntelInfo) {
	value = strings.ToLower(value)
	info.Source = strings.ToLower(info.Source)

	if _, ok := s.threatIntelDB[value]; !ok {
		s.threatIntelDB[value] = []ThreatIntelInfo{}
	}
	s.threatIntelDB[value] = append(s.threatIntelDB[value], info)
}

func (s *EnricherService) BatchAddThreatIntel(iocs []ThreatIntelInfo) {
	for _, ioc := range iocs {
		s.AddThreatIntel(models.IoCTypeDomain, ioc.Description, ioc)
	}
}

func (s *EnricherService) IsThreat(value string) bool {
	return s.LookupThreatIntel(value) != nil
}

func (s *EnricherService) GetThreatLevel(value string) string {
	intel := s.LookupThreatIntel(value)
	if intel == nil {
		return "unknown"
	}

	if intel.Confidence >= 0.8 {
		return "high"
	} else if intel.Confidence >= 0.5 {
		return "medium"
	} else {
		return "low"
	}
}

type AssetEnricher struct {
	assetDB map[string]map[string]interface{}
}

func NewAssetEnricher() *AssetEnricher {
	return &AssetEnricher{
		assetDB: make(map[string]map[string]interface{}),
	}
}

func (e *AssetEnricher) EnrichEvent(event *models.SecurityEvent) {
	for _, assetID := range event.AssetIDs {
		if asset := e.GetAsset(assetID); asset != nil {
			if event.RawData == nil {
				event.RawData = make(map[string]interface{})
			}
			event.RawData["asset_info"] = asset
		}
	}
}

func (e *AssetEnricher) GetAsset(assetID string) map[string]interface{} {
	return e.assetDB[assetID]
}

func (e *AssetEnricher) AddAsset(assetID string, info map[string]interface{}) {
	e.assetDB[assetID] = info
}

func (e *AssetEnricher) SearchByIP(ip string) []map[string]interface{} {
	var results []map[string]interface{}
	for _, asset := range e.assetDB {
		if assetIP, ok := asset["ip"].(string); ok {
			if assetIP == ip {
				results = append(results, asset)
			}
		}
	}
	return results
}

func (e *AssetEnricher) SearchByHostname(hostname string) []map[string]interface{} {
	var results []map[string]interface{}
	for _, asset := range e.assetDB {
		if h, ok := asset["hostname"].(string); ok {
			if strings.Contains(strings.ToLower(h), strings.ToLower(hostname)) {
				results = append(results, asset)
			}
		}
	}
	return results
}
