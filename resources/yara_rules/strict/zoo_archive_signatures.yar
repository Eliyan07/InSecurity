// resources/yara_rules/strict/zoo_archive_signatures.yar
// Tight signatures for known malware archives observed in local sample corpora.
// These are exact archive-entry matches, not generic filename heuristics.

rule Archive_ZeusBanking_Zip_Lure {
    meta:
        description = "Zeus banking trojan ZIP with disguised PDF executable payload"
        severity = "critical"
        family = "Zeus"

    strings:
        $zip = { 50 4B 03 04 }
        $payload = "invoice_2318362983713_823931342io.pdf.exe" ascii

    condition:
        $zip at 0 and $payload
}
