package main

import (
	"fmt"

	peparser "github.com/saferwall/pe"
)

func LocateRCDataEnd(pe_path string) int64 {
	pe, err := peparser.New(pe_path, &peparser.Options{
		Fast:                       false,
		SectionEntropy:             false,
		DisableCertValidation:      true,
		DisableSignatureValidation: true,
		OmitExportDirectory:        true,
		OmitResourceDirectory:      false,
		OmitSecurityDirectory:      true,
		OmitRelocDirectory:         true,
		OmitDebugDirectory:         true,
		OmitArchitectureDirectory:  true,
		OmitGlobalPtrDirectory:     true,
		OmitTLSDirectory:           true,
		OmitLoadConfigDirectory:    true,
		OmitBoundImportDirectory:   true,
		OmitIATDirectory:           true,
		OmitDelayImportDirectory:   true,
		OmitCLRHeaderDirectory:     true,
	})
	if err != nil {
		fmt.Println("[!] Error while opening file!")
		return -1
	}
	defer pe.Close()

	if err = pe.Parse(); err != nil {
		fmt.Println("[!] Error while parsing file!")
		return -1
	}
	
	// https://github.com/Nuitka/Nuitka/blob/b4ae0b6701533c22be732837db49ce5b5f5a90ce/nuitka/build/static_src/OnefileBootstrap.c#L216
	if pe.HasResource {
		for _, entry := range pe.Resources.Entries {
			if entry.ID == peparser.RTRCdata &&
				entry.IsResourceDir &&
				len(entry.Directory.Entries) == 1 &&
				entry.Directory.Entries[0].ID == 27 {
				rcdataEntry := entry.Directory.Entries[0]
				if rcdataEntry.IsResourceDir &&
					len(rcdataEntry.Directory.Entries) == 1 &&
					!rcdataEntry.Directory.Entries[0].IsResourceDir {
					return int64(pe.GetOffsetFromRva(rcdataEntry.Directory.Entries[0].Data.Struct.OffsetToData) + rcdataEntry.Directory.Entries[0].Data.Struct.Size)
				}
			}
		}
	}
	return -1
}
