//! The Turkish rendering of the page the supplier reads.
//!
//! Kept beside the English text rather than derived from it. Instructions are the
//! one document where a phrase-by-phrase translation reads worst: "Right-click the
//! folder, choose Send to, then Compressed (zipped) folder" has to name what the
//! Turkish Windows menu actually says, not what the English one says. So this is
//! written as its own page, and the tests check that both carry the same promises
//! rather than the same sentences.
//!
//! Plain text, because it has to survive being pasted into an e-mail body or opened
//! in Notepad. UTF-8 rather than ASCII: Turkish without its diacritics is legible
//! but reads as carelessness, which is the wrong first impression for a program a
//! stranger is being asked to run over their own files.

/// The Turkish `ÖNCE BUNU OKUYUN.txt`.
pub fn text(challenge: &cl_case::Challenge, scanner_included: bool) -> String {
    let opening = if challenge.vendor_label.trim().is_empty() {
        "Yapay zekâ sistemlerinizden birinin nasıl kurulduğunu göstermeniz istendi.".to_string()
    } else {
        format!(
            "{} adlı kuruluştan, yapay zekâ sistemlerinden birinin nasıl kurulduğunu göstermesi istendi.",
            challenge.vendor_label
        )
    };
    let run_line = if scanner_included {
        "2. Bu klasördeki  cladeon-screen.exe  dosyasına çift tıklayın."
    } else {
        "2. Size gönderilen Cladeon Tarayıcı programına çift tıklayın."
    };

    format!(
        "BU NEDİR\n\
         ========\n\
         \n\
         {opening}\n\
         Bu klasörde, seçtiğiniz klasörlere bakan ve tek bir özet dosyası yazan küçük\n\
         bir program var. O dosyayı geri gönderirsiniz. Hiçbir şey yüklenmez.\n\
         \n\
         Kontrol edilen ifade:\n\
         \n\
             \"{claim}\"\n\
         \n\
         Dosya numarası: {case}\n\
         Yanıt için son tarih: {expires}\n\
         \n\
         \n\
         BU PROGRAMIN YAPMAYACAKLARI\n\
         ===========================\n\
         \n\
         - İnternete bağlanmaz. Hiçbir şey, hiçbir zaman yüklenmez.\n\
         - Model dosyalarınızı açmaz, yüklemez veya çalıştırmaz.\n\
         - Model ağırlıklarınızı, eğitim verilerinizi, kaynak kodunuzu veya\n\
           istemlerinizi kopyalamaz.\n\
         - Yönetici izni istemez ve hiçbir şey kurmaz.\n\
         - Parolaları, API anahtarlarını ve Windows kullanıcı adınızı otomatik olarak\n\
           kaldırır ve kaldırdığı her şeyin listesini size gösterir.\n\
         \n\
         Herhangi bir şey okumadan önce, tam olarak neyin gönderileceğini size gösterir.\n\
         O noktada durabilirsiniz.\n\
         \n\
         \n\
         NE YAPMALISINIZ\n\
         ===============\n\
         \n\
         1. Bu klasördeki her şeyi bir arada tutun.\n\
         {run_line}\n\
         3. Ekrandaki beş adımı izleyin. Modeli ve eğitim kayıtlarını içeren\n\
            klasörleri seçin.\n\
         4. Program, sonunda .clade uzantılı tek bir dosya kaydeder.\n\
         5. E-postayı yanıtlayın ve o dosyayı hiç değiştirmeden ekleyin.\n\
         \n\
         Dosyanın adını değiştirmeyin, açıp yeniden kaydetmeyin, ekran görüntüsü veya\n\
         çıktı göndermeyin. Dosya, bunların bozacağı kontroller taşır.\n\
         \n\
         \n\
         BİR ŞEYİ GÖSTEREMİYORSANIZ\n\
         ==========================\n\
         \n\
         Onu dışarıda bırakın. Program klasörleri hariç tutmanıza izin verir ve yalnızca\n\
         bir şeyin hariç tutulduğunu kaydeder; içinde ne olduğunu asla kaydetmez.\n\
         \"Yeterli kanıt yok\" diyen bir rapor olağan bir sonuçtur ve aleyhinize bir\n\
         bulgu olarak değerlendirilmez.\n\
         \n\
         \n\
         {statement}\n",
        opening = opening,
        claim = challenge.exact_claim_text,
        case = challenge.case_id,
        expires = challenge.expires_at.to_rfc3339(),
        run_line = run_line,
        statement = cl_core::REQUIRED_STATEMENT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_core::ids::{CaseId, Nonce};
    use cl_core::time::Timestamp;

    fn sample() -> cl_case::Challenge {
        cl_case::Challenge::new(
            CaseId::parse("CL-2026-0F3A9C").unwrap(),
            Nonce::parse(&"a1".repeat(16)).unwrap(),
            "Acme Analitik A.Ş.",
            "Kendi modelimizi eğittik.",
            Timestamp::parse_rfc3339("2026-09-02T13:00:00Z").unwrap(),
            14,
            vec!["adapter_config".into()],
            None,
            Some(cl_core::vocab::WeightOrigin::RandomInitializationClaimed),
        )
    }

    #[test]
    fn it_leads_with_what_the_program_will_not_do() {
        // Same ordering promise as the English page: reassurance before instruction.
        let t = text(&sample(), true);
        let will_not = t.find("YAPMAYACAKLARI").expect("section present");
        let what_to_do = t.find("NE YAPMALISINIZ").expect("section present");
        assert!(will_not < what_to_do);
    }

    #[test]
    fn it_quotes_the_claim_the_case_and_the_deadline() {
        let t = text(&sample(), true);
        assert!(t.contains("Kendi modelimizi eğittik."));
        assert!(t.contains("CL-2026-0F3A9C"));
        assert!(t.contains("2026-09-16"), "the reply-by date must be visible");
    }

    #[test]
    fn it_says_that_withholding_is_allowed() {
        // A supplier who feels cornered does not run it at all, in any language.
        let t = text(&sample(), true);
        assert!(t.contains("GÖSTEREMİYORSANIZ"));
        assert!(t.contains("aleyhinize bir\n         bulgu olarak değerlendirilmez") || t.contains("değerlendirilmez"));
    }

    #[test]
    fn it_carries_the_required_statement() {
        // The statement itself stays in English: it is the legal text the report
        // carries verbatim, and a translated copy would be a different statement.
        assert!(text(&sample(), true).contains("does not establish intent"));
    }

    #[test]
    fn it_is_written_in_turkish_with_its_diacritics_intact() {
        let t = text(&sample(), true);
        for ch in ['ç', 'ğ', 'ı', 'İ', 'ö', 'ş', 'ü'] {
            assert!(t.contains(ch), "no `{ch}`: the diacritics were stripped somewhere");
        }
    }

    #[test]
    fn it_adapts_when_the_scanner_is_not_bundled() {
        assert!(text(&sample(), true).contains("cladeon-screen.exe"));
        assert!(!text(&sample(), false).contains("cladeon-screen.exe"));
    }

    #[test]
    fn it_uses_no_forbidden_language() {
        // The guard is English-word based, so this checks the untranslated fragments
        // - the claim, the case id and the required statement - rather than proving
        // anything about the Turkish. Kept because those fragments are the ones a
        // buyer can influence.
        assert_eq!(cl_core::vocab::forbidden_language(&text(&sample(), true)), None);
    }
}
