//! Interface language.
//!
//! # What is translated, and what is deliberately not
//!
//! The **interface** is translated. The **evidence is not**, and that is a decision
//! rather than an omission.
//!
//! `report.json` is the authoritative document, and the values inside it -
//! `contradicted_within_observed_scope`, `weight_origin`, and the rest - are
//! identifiers, not prose. They sit inside bytes that are hashed, signed, and
//! re-derived by the verifier. Translating them would change the canonical bytes and
//! break the very checks the product exists to perform.
//!
//! There is a second reason, which would apply even if the bytes did not matter. A
//! report travels between two parties who need not share a language: a buyer in one
//! country asks a supplier in another. If the report were written in whichever
//! language the supplier happened to have selected, the person who commissioned it
//! could not read their own evidence. So the language here is a property of the
//! **machine**, never of the case.
//!
//! # Why lookup by English text rather than by key
//!
//! Call sites pass the English sentence, and it is looked up. The usual objection is
//! that a typo silently falls back to English instead of failing loudly - which is
//! true, and is why `every_display_string_in_the_interface_is_translated` reads the
//! interface sources and fails on any string with no entry. The gain is that the
//! English source stays legible at the call site: a reader of `home()` sees the
//! sentence the user sees, not `t(Key::HomeBodyLine2)`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    Tr,
}

impl Lang {
    pub const ALL: &'static [Lang] = &[Lang::En, Lang::Tr];

    /// The tag stored in the settings file.
    pub fn as_str(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Tr => "tr",
        }
    }

    /// What this language calls itself.
    ///
    /// Endonyms, always. Someone looking for Turkish is looking for the word
    /// "Türkçe"; a menu that offers them "Turkish" is a menu they cannot read.
    pub fn endonym(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Tr => "Türkçe",
        }
    }

    pub fn parse(s: &str) -> Option<Lang> {
        match s.trim().to_lowercase().as_str() {
            "en" => Some(Lang::En),
            "tr" => Some(Lang::Tr),
            _ => None,
        }
    }

    /// Guess from the operating system, for a first run with nothing stored.
    ///
    /// Only the primary subtag is read, so `tr-TR`, `tr_TR.UTF-8` and `tr` all land
    /// on Turkish. Anything unrecognised is English rather than an error: a wrong
    /// guess costs one click on a picker that is always visible.
    pub fn from_os() -> Lang {
        for var in ["LANG", "LC_ALL", "LC_MESSAGES"] {
            if let Some(v) = std::env::var_os(var).and_then(|v| v.into_string().ok()) {
                if let Some(l) = Lang::parse(v.split(['-', '_', '.']).next().unwrap_or("")) {
                    return l;
                }
            }
        }
        #[cfg(windows)]
        if let Some(l) = windows_ui_language() {
            return l;
        }
        Lang::En
    }
}

/// Read the Windows display language without linking a Win32 crate.
///
/// `Get-UICulture` would be exact, but spawning PowerShell to read a setting is a
/// process this product does not otherwise start, and it would show a console flash
/// on a GUI application. The environment is checked instead, and English is a safe
/// default when nothing says otherwise.
#[cfg(windows)]
fn windows_ui_language() -> Option<Lang> {
    // `USERPROFILE` and friends carry no locale, so there is nothing better to read
    // here without a Win32 call. Kept as a named seam so the improvement has an
    // obvious home rather than being scattered through `from_os`.
    None
}

/// Where the chosen language is remembered.
///
/// Per user, beside the other per-user state, and deliberately not beside the
/// executable: an installed copy lives somewhere read-only, and a preference that
/// cannot be saved is worse than none because the user re-picks it every launch.
pub fn settings_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
    })?;
    Some(base.join("Cladeon").join("language"))
}

/// The language to start in: what was chosen last, else what the system suggests.
pub fn load() -> Lang {
    settings_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| Lang::parse(&s))
        .unwrap_or_else(Lang::from_os)
}

/// Remember the choice. A failure here is not worth interrupting anyone over: the
/// language still changes for this session, it simply is not remembered.
pub fn save(l: Lang) {
    if let Some(p) = settings_path() {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(p, l.as_str());
    }
}

/// Translate a display string. Unknown strings are returned unchanged.
pub fn t(lang: Lang, en: &str) -> &str {
    match lang {
        Lang::En => en,
        Lang::Tr => table().get(en).copied().unwrap_or(en),
    }
}

fn table() -> &'static HashMap<&'static str, &'static str> {
    static T: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    T.get_or_init(|| TR.iter().copied().collect())
}

/// English source text paired with its Turkish rendering.
///
/// Kept as one flat list rather than grouped per screen, because the same sentence
/// turns up on more than one screen and a grouped table invites two translations of
/// it that drift apart.
pub const TR: &[(&str, &str)] = &[
    // ---- the required statement --------------------------------------------
    //
    // Translated on screen, left in English inside the bundle. In the report it is
    // part of a hashed, signed document and cannot move; on screen its entire job is
    // to be understood, and a caveat in a language the reader does not have is
    // decoration that looks like one.
    (
        "This Stage-1 report evaluates consistency within vendor-supplied evidence. It does not establish intent, independently verify the production environment, or prove historical training events that cannot be reconstructed from the supplied artifacts.",
        "Bu Aşama-1 raporu, tedarikçinin sunduğu kanıtların kendi içindeki tutarlılığını değerlendirir. Niyet ortaya koymaz, üretim ortamını bağımsız olarak doğrulamaz ve sunulan belgelerden yeniden kurulamayan geçmiş eğitim olaylarını kanıtlamaz.",
    ),

    // ---- shared chrome ----------------------------------------------------
    ("Cladeon Screen", "Cladeon Tarayıcı"),
    ("Back", "Geri"),
    ("Continue", "Devam"),
    ("Something went wrong", "Bir sorun oluştu"),
    ("Dismiss", "Kapat"),
    ("Copy location", "Konumu kopyala"),
    ("Copy checksum", "Sağlama toplamını kopyala"),
    ("Language", "Dil"),
    ("Home", "Ana sayfa"),
    (
        "No internet connection is used.\nYour files are never run.",
        "İnternet bağlantısı kullanılmaz.\nDosyalarınız hiçbir zaman çalıştırılmaz.",
    ),

    // ---- vendor: step rail ------------------------------------------------
    ("What this is", "Bu nedir"),
    ("Your folders", "Klasörleriniz"),
    ("Before we start", "Başlamadan önce"),
    ("Scanning", "Taranıyor"),
    ("Send it back", "Geri gönderin"),

    // ---- vendor: welcome --------------------------------------------------
    ("Show how your AI system was built", "Yapay zekâ sisteminizin nasıl kurulduğunu gösterin"),
    (
        "This program looks at folders you choose and writes one file describing what it found. You send that file back. It takes a few minutes.",
        "Bu program seçtiğiniz klasörlere bakar ve bulduklarını anlatan tek bir dosya yazar. O dosyayı geri gönderirsiniz. Birkaç dakika sürer.",
    ),
    ("Asked by", "İsteyen"),
    ("Reference", "Referans"),
    ("The statement being checked", "Kontrol edilen ifade"),
    (
        "Taken from the request. You are not asked to restate it.",
        "İstekten alınmıştır. Yeniden ifade etmeniz istenmez.",
    ),
    ("What it never does", "Asla yapmadıkları"),
    (
        "-  It does not connect to the internet. Nothing is uploaded.",
        "-  İnternete bağlanmaz. Hiçbir şey yüklenmez.",
    ),
    (
        "-  It does not run, open or load your model files.",
        "-  Model dosyalarınızı çalıştırmaz, açmaz veya yüklemez.",
    ),
    (
        "-  It does not copy your weights, your data, your code or your prompts.",
        "-  Ağırlıklarınızı, verilerinizi, kodunuzu veya istemlerinizi kopyalamaz.",
    ),
    (
        "-  It removes passwords, API keys and your Windows user name.",
        "-  Parolaları, API anahtarlarını ve Windows kullanıcı adınızı kaldırır.",
    ),
    (
        "Before it reads anything, it shows you exactly what would be sent.",
        "Herhangi bir şey okumadan önce, tam olarak neyin gönderileceğini size gösterir.",
    ),

    // ---- vendor: missing request ------------------------------------------
    ("The request file is missing", "İstek dosyası eksik"),
    (
        "Whoever asked you for this sent a small file called challenge.json. It should sit in the same folder as this program.",
        "Bunu sizden isteyen kişi challenge.json adında küçük bir dosya gönderdi. Bu dosyanın, bu programla aynı klasörde olması gerekir.",
    ),
    ("What to do", "Ne yapmalı"),
    (
        "Go back to their e-mail and save the whole folder they attached, keeping the files together. Then open this program from inside that folder.",
        "Gönderdikleri e-postaya dönün ve ekteki klasörün tamamını, dosyaları bir arada tutarak kaydedin. Sonra bu programı o klasörün içinden açın.",
    ),
    ("Find the file myself", "Dosyayı kendim bulayım"),
    ("Open the request file you were sent", "Size gönderilen istek dosyasını açın"),
    ("Request file", "İstek dosyası"),
    (
        "That folder does not hold a request this program can read. Look for the folder containing challenge.json.",
        "O klasörde bu programın okuyabileceği bir istek yok. challenge.json dosyasını içeren klasörü arayın.",
    ),
    ("The case identifier is not valid.", "Dosya numarası geçerli değil."),

    // ---- vendor: folders --------------------------------------------------
    ("Choose what to show", "Neyi göstereceğinizi seçin"),
    (
        "Pick the folders holding your model and its training records. Nothing outside these folders is looked at.",
        "Modelinizi ve eğitim kayıtlarını içeren klasörleri seçin. Bu klasörlerin dışına bakılmaz.",
    ),
    ("Add a folder…", "Klasör ekle…"),
    ("No folders chosen yet.", "Henüz klasör seçilmedi."),
    ("Remove", "Kaldır"),
    (
        "Leave a folder out (most people do not need this)",
        "Bir klasörü hariç tutun (çoğu kişinin buna ihtiyacı olmaz)",
    ),
    (
        "Anything you exclude is recorded as excluded by you. It is not hidden, but its contents are never read.",
        "Hariç tuttuğunuz her şey, sizin tarafınızdan hariç tutulmuş olarak kaydedilir. Gizlenmez, ancak içeriği hiçbir zaman okunmaz.",
    ),
    ("Exclude a folder...", "Bir klasörü hariç tut..."),

    // ---- vendor: preflight ------------------------------------------------
    ("Before anything is read", "Hiçbir şey okunmadan önce"),
    ("Looking at what is there. Nothing has been read yet.", "Neler olduğuna bakılıyor. Henüz hiçbir şey okunmadı."),
    (
        "This is everything found in the folders you chose. No file has been read and nothing has been written.",
        "Bu, seçtiğiniz klasörlerde bulunan her şeydir. Hiçbir dosya okunmadı ve hiçbir şey yazılmadı.",
    ),
    ("Kind of file (by its name)", "Dosya türü (adına göre)"),
    ("Folders with the most files", "En çok dosya içeren klasörler"),
    (
        "Every file adds time to the scan. If one of these does not hold your model or its training records, you can leave it out. The report will say a folder was left out, never what was in it.",
        "Her dosya taramaya süre ekler. Bunlardan biri modelinizi veya eğitim kayıtlarınızı içermiyorsa dışarıda bırakabilirsiniz. Rapor bir klasörün dışarıda bırakıldığını söyler, içinde ne olduğunu asla söylemez.",
    ),
    ("Leave this out", "Bunu dışarıda bırak"),
    ("files", "dosya"),
    ("Count", "Adet"),
    ("Size", "Boyut"),
    ("Total", "Toplam"),
    (" days", " gün"),
    ("PDF", "PDF belgesi"),
    (
        "These are formats that can run code when loaded. Cladeon records their name, size and checksum and never reads inside them.",
        "Bunlar yüklendiğinde kod çalıştırabilen biçimlerdir. Cladeon yalnızca adlarını, boyutlarını ve sağlama toplamlarını kaydeder; içlerini asla okumaz.",
    ),
    ("What will be in the file you send back", "Geri göndereceğiniz dosyada neler olacak"),
    (
        "•  Folder and file names, shortened so your real paths are hidden.",
        "•  Klasör ve dosya adları; gerçek yollarınız gizlenecek şekilde kısaltılmış olarak.",
    ),
    ("•  File sizes and checksums.", "•  Dosya boyutları ve sağlama toplamları."),
    (
        "•  Settings read from configuration files, such as a model's size.",
        "•  Yapılandırma dosyalarından okunan ayarlar; örneğin bir modelin boyutu.",
    ),
    ("•  The conclusions drawn from those.", "•  Bunlardan çıkarılan sonuçlar."),
    ("What will not be", "Neler olmayacak"),
    (
        "•  Your model weights, training data, source code and prompts.",
        "•  Model ağırlıklarınız, eğitim verileriniz, kaynak kodunuz ve istemleriniz.",
    ),
    (
        "•  Any password, key or token — removed before it reaches the file.",
        "•  Herhangi bir parola, anahtar veya belirteç — dosyaya ulaşmadan önce kaldırılır.",
    ),
    (
        "•  Your Windows user name and any full path from this computer.",
        "•  Windows kullanıcı adınız ve bu bilgisayardaki tam yolların hiçbiri.",
    ),
    ("Things this scan will not be able to see", "Bu taramanın göremeyeceği şeyler"),
    ("Scan and create the file", "Tara ve dosyayı oluştur"),

    // ---- vendor: running --------------------------------------------------
    ("Files seen", "Görülen dosya"),
    ("Data examined", "İncelenen veri"),
    ("Data checksummed", "Sağlaması alınan veri"),
    (
        "Counts are of real work done, not an estimate. Large model files take the longest.",
        "Sayılar tahmin değil, gerçekten yapılan işi gösterir. En uzun süreyi büyük model dosyaları alır.",
    ),
    ("This may take a while", "Bu biraz zaman alabilir"),
    ("Files and folders found", "Bulunan dosya ve klasörler"),
    (
        "A folder with many files can take several minutes, sometimes longer, because Windows checks each file as it is opened. The counts above keep moving while it works. You can use your computer in the meantime; just leave this window open.",
        "Çok sayıda dosya içeren bir klasör birkaç dakika, bazen daha uzun sürebilir, çünkü Windows her dosyayı açılırken denetler. Yukarıdaki sayılar çalıştığı sürece artmaya devam eder. Bu arada bilgisayarınızı kullanabilirsiniz; yalnızca bu pencereyi açık bırakın.",
    ),
    (
        "This usually takes a few seconds. A folder with a very large number of files can take a minute or two.",
        "Bu genellikle birkaç saniye sürer. Çok fazla dosya içeren bir klasör bir iki dakika sürebilir.",
    ),

    // ---- vendor: done -----------------------------------------------------
    ("Done — now send the file back", "Bitti — şimdi dosyayı geri gönderin"),
    ("Your file is saved here", "Dosyanız buraya kaydedildi"),
    (
        "Attach that one file to your reply. Do not rename it, open it and save it again, or send a screenshot — any of those breaks the checks it carries.",
        "Yanıtınıza yalnızca o dosyayı ekleyin. Adını değiştirmeyin, açıp yeniden kaydetmeyin ve ekran görüntüsü göndermeyin — bunların her biri dosyanın taşıdığı kontrolleri bozar.",
    ),
    ("What was looked at", "Nelere bakıldı"),
    ("Files", "Dosyalar"),
    ("Data", "Veri"),
    ("Coverage", "Kapsam"),
    ("Removed before sending", "Gönderilmeden önce kaldırıldı"),
    ("nothing needed removing", "kaldırılması gereken bir şey yoktu"),
    ("What the files showed", "Dosyaların gösterdikleri"),
    ("Scan again", "Yeniden tara"),
    (
        "If it says there was not enough evidence",
        "Yeterli kanıt yoktu diyorsa",
    ),
    (
        "It means the files that would answer that question were not in the folders you picked. That is a normal result. You can go back, add more folders and run it again.",
        "Bu, o soruyu yanıtlayacak dosyaların seçtiğiniz klasörlerde bulunmadığı anlamına gelir. Bu normal bir sonuçtur. Geri dönüp klasör ekleyebilir ve yeniden çalıştırabilirsiniz.",
    ),

    // ---- auditor: home ----------------------------------------------------
    ("Check how a vendor built their AI", "Bir tedarikçinin yapay zekâsını nasıl kurduğunu denetleyin"),
    (
        "You pick what a supplier says they built. They run a small program over their own files. Cladeon tells you how well the two fit.",
        "Bir tedarikçinin ne kurduğunu söylediğini seçersiniz. Onlar kendi dosyaları üzerinde küçük bir program çalıştırır. Cladeon ikisinin ne kadar örtüştüğünü söyler.",
    ),
    ("Start a new check", "Yeni bir denetim başlat"),
    ("Open a file a vendor sent back", "Tedarikçinin gönderdiği dosyayı aç"),
    ("How to use this (PDF)", "Bu nasıl kullanılır (PDF)"),
    ("How it works", "Nasıl çalışır"),
    (
        "1.  You answer one question: what do they say they built?",
        "1.  Tek bir soruyu yanıtlarsınız: ne kurduklarını söylüyorlar?",
    ),
    ("2.  Cladeon makes a folder. You e-mail it to them.", "2.  Cladeon bir klasör oluşturur. Onlara e-postayla gönderirsiniz."),
    (
        "3.  They double-click one program and send back one file.",
        "3.  Onlar tek bir programa çift tıklar ve tek bir dosya geri gönderir.",
    ),
    ("4.  You open that file here and read the report.", "4.  O dosyayı burada açar ve raporu okursunuz."),
    ("What this can and cannot tell you", "Bunun size söyleyebilecekleri ve söyleyemeyecekleri"),
    (
        "It reports whether the files fit the claim. It cannot see what was not sent, and it does not decide what anyone intended. Its most common answer is that there was not enough evidence to tell, which is a real answer.",
        "Dosyaların iddiaya uyup uymadığını bildirir. Gönderilmeyeni göremez ve kimsenin niyetine karar vermez. En sık verdiği yanıt, karar vermeye yetecek kanıt bulunmadığıdır; bu da gerçek bir yanıttır.",
    ),

    // ---- auditor: new case ------------------------------------------------
    ("What are they saying they built?", "Ne kurduklarını söylüyorlar?"),
    ("Pick whichever is closest to what you were told.", "Size söylenene en yakın olanı seçin."),
    ("They trained their own model", "Kendi modellerini eğittiler"),
    ("They built on someone else's model", "Başkasının modeli üzerine kurdular"),
    ("They copied a bigger model's behaviour", "Daha büyük bir modelin davranışını kopyaladılar"),
    ("They did not say", "Belirtmediler"),
    ("The statement that gets tested", "Sınanacak ifade"),
    ("We trained our own model.", "Kendi modelimizi eğittik."),
    (
        "We built our system on an existing model from someone else.",
        "Sistemimizi başkasına ait mevcut bir modelin üzerine kurduk.",
    ),
    (
        "We copied the behaviour of a larger model into our own.",
        "Daha büyük bir modelin davranışını kendi modelimize kopyaladık.",
    ),
    (
        "No claim about how this model was built has been recorded.",
        "Bu modelin nasıl kurulduğuna dair bir iddia kaydedilmemiştir.",
    ),
    ("Ask them to reply within", "Yanıt için tanınan süre"),
    ("Create the folder to send", "Gönderilecek klasörü oluştur"),

    // ---- auditor: kit ready -----------------------------------------------
    ("Ready to send", "Gönderime hazır"),
    ("Case reference", "Dosya numarası"),
    ("Folder created", "Klasör oluşturuldu"),
    ("The folder location is on your clipboard.", "Klasörün konumu panoya kopyalandı."),
    ("What to do now", "Şimdi ne yapmalı"),
    ("1.  Zip that folder.", "1.  O klasörü sıkıştırın."),
    ("2.  E-mail it to your contact at the vendor.", "2.  Tedarikçideki muhatabınıza e-postayla gönderin."),
    (
        "3.  Tell them to open it and read \"READ ME FIRST\".",
        "3.  Açıp \"READ ME FIRST\" dosyasını okumalarını söyleyin.",
    ),
    ("4.  They send back one file ending in .clade", "4.  Size .clade uzantılı tek bir dosya geri gönderirler"),
    ("The scanner program was not included", "Tarayıcı programı eklenmedi"),
    (
        "cladeon-screen.exe was not found next to this application, so the folder contains only the request. Copy the scanner in beside it before sending, or the vendor will have nothing to run.",
        "cladeon-screen.exe bu uygulamanın yanında bulunamadı, bu yüzden klasörde yalnızca istek var. Göndermeden önce tarayıcıyı klasöre kopyalayın; aksi hâlde tedarikçinin çalıştıracağı bir şey olmaz.",
    ),
    ("Start another check", "Başka bir denetim başlat"),
    ("Open a returned file", "Geri gelen dosyayı aç"),

    // ---- auditor: report --------------------------------------------------
    ("What the vendor sent back", "Tedarikçinin gönderdikleri"),
    ("Supplier", "Tedarikçi"),
    ("not recorded", "kaydedilmedi"),
    ("Case", "Dosya"),
    ("File", "Dosya adı"),
    ("The claim being tested", "Sınanan iddia"),
    ("Five separate checks", "Beş ayrı kontrol"),
    (
        "These answer different questions. A file can be perfectly intact and still not prove much; both of those are shown, and neither cancels the other.",
        "Bunlar farklı soruları yanıtlar. Bir dosya tamamen bozulmamış olabilir ve yine de fazla bir şey göstermeyebilir; her ikisi de ayrı ayrı belirtilir ve biri diğerini geçersiz kılmaz.",
    ),
    ("Has the file been altered?", "Dosya değiştirilmiş mi?"),
    ("Unchanged since the vendor created it.", "Tedarikçi oluşturduğundan beri değişmemiş."),
    ("Something was edited after it was created.", "Oluşturulduktan sonra bir şey düzenlenmiş."),
    ("Part of the bundle is missing.", "Paketin bir kısmı eksik."),
    ("The file could not be read at all.", "Dosya hiç okunamadı."),
    ("Does it answer your request?", "İsteğinize yanıt veriyor mu?"),
    ("It is signed and tied to the request you issued.", "İmzalanmış ve gönderdiğiniz isteğe bağlanmış."),
    (
        "It names a request, but nothing proves it was yours.",
        "Bir isteğe atıfta bulunuyor, ancak bunun sizinki olduğunu gösteren bir şey yok.",
    ),
    ("It answers no recorded request.", "Kayıtlı hiçbir isteğe yanıt vermiyor."),
    ("The request had expired when this was checked.", "Kontrol edildiğinde isteğin süresi dolmuştu."),
    ("The signature does not check out.", "İmza doğrulanmıyor."),
    ("This answers a different case.", "Bu, başka bir dosyaya yanıt veriyor."),
    ("Was the PDF rebuilt?", "PDF yeniden oluşturulmuş mu?"),
    ("The PDF still carries its original markings.", "PDF hâlâ özgün işaretlerini taşıyor."),
    (
        "The PDF claims markings it does not carry. It has been rebuilt or copied.",
        "PDF, taşımadığı işaretleri olduğunu bildiriyor. Yeniden oluşturulmuş veya kopyalanmış.",
    ),
    ("No markings to check.", "Kontrol edilecek işaret yok."),
    ("How much did they show?", "Ne kadarını gösterdiler?"),
    (
        "How much of the selected folders the scan managed to read.",
        "Seçilen klasörlerin ne kadarının taranabildiği.",
    ),
    ("Do the conclusions follow?", "Sonuçlar kanıttan çıkıyor mu?"),
    ("checked and consistent", "kontrol edildi, tutarlı"),
    ("DOES NOT FOLLOW", "ÇIKMIYOR"),
    ("could not be re-checked", "yeniden kontrol edilemedi"),
    (
        "Cladeon re-derives the findings from the evidence in the file and compares them with what the file claims.",
        "Cladeon, bulguları dosyadaki kanıttan yeniden türetir ve dosyanın bildirdikleriyle karşılaştırır.",
    ),
    (
        "The stated findings do not follow from the evidence in this file",
        "Bildirilen bulgular, bu dosyadaki kanıttan çıkmıyor",
    ),
    (
        "This is what an edited report looks like even when every checksum matches. Ask the vendor to run the scan again and send the untouched result.",
        "Bütün sağlama toplamları tutsa bile düzenlenmiş bir rapor böyle görünür. Tedarikçiden taramayı yeniden çalıştırmasını ve sonucu hiç dokunmadan göndermesini isteyin.",
    ),
    ("What the evidence supports", "Kanıtın desteklediği"),
    ("No conclusions were recorded.", "Hiçbir sonuç kaydedilmemiş."),
    ("Before you act on this", "Buna göre hareket etmeden önce"),
    (
        "This is a self-scan: the vendor chose which folders to show, on a machine you do not control. It cannot establish that the folders scanned are the system actually in production. Treat it as a screen that tells you what to ask next, not as an audit.",
        "Bu bir öz-taramadır: hangi klasörlerin gösterileceğini, sizin denetiminizde olmayan bir makinede tedarikçi seçmiştir. Taranan klasörlerin gerçekten üretimdeki sistem olduğunu kanıtlayamaz. Bunu bir denetim değil, bundan sonra ne soracağınızı gösteren bir ön eleme olarak değerlendirin.",
    ),
    ("Open another file", "Başka bir dosya aç"),
    ("Copy file location", "Dosya konumunu kopyala"),
    ("The file location is on your clipboard.", "Dosyanın konumu panoya kopyalandı."),
    ("Copy evidence fingerprint", "Kanıt parmak izini kopyala"),
    (
        "The evidence fingerprint is on your clipboard. Two scans of unchanged evidence share it.",
        "Kanıt parmak izi panoya kopyalandı. Değişmemiş kanıtın iki taraması aynı parmak izini taşır.",
    ),
    ("Save the instructions", "Yönergeyi kaydet"),

    // ---- shared: bands and facets -----------------------------------------
    (
        "Several independent pieces of evidence agree with this part of the claim.",
        "Birbirinden bağımsız birkaç kanıt, iddianın bu bölümüyle uyuşuyor.",
    ),
    (
        "The evidence supplied fits this part of the claim well.",
        "Sunulan kanıt, iddianın bu bölümüne iyi uyuyor.",
    ),
    ("The evidence fits, but there is not much of it.", "Kanıt uyuyor, ancak miktarı az."),
    (
        "There is real supporting evidence, but not enough to name the method used.",
        "Gerçek destekleyici kanıt var, ancak kullanılan yöntemi adlandırmaya yetmiyor.",
    ),
    (
        "Not enough was supplied to answer this. That is a normal result, not a mark against anyone.",
        "Bunu yanıtlamaya yetecek kadarı sunulmadı. Bu normal bir sonuçtur, kimse aleyhine bir kayıt değildir.",
    ),
    (
        "A file that was examined does not fit the claim being checked.",
        "İncelenen bir dosya, kontrol edilen iddiaya uymuyor.",
    ),
    (
        "The kind of file needed to answer this was not in the folders that were scanned.",
        "Bunu yanıtlamak için gereken türde bir dosya, taranan klasörlerde yoktu.",
    ),
    ("Where the weights came from", "Ağırlıkların nereden geldiği"),
    ("How the weights were changed", "Ağırlıkların nasıl değiştirildiği"),
    ("What kind of training", "Eğitimin türü"),
    ("What else runs at answer time", "Yanıt sırasında başka neler çalışıyor"),

    // ---- vendor: kinds of file shown in the preflight table ----------------
    ("Model weights (SafeTensors)", "Model ağırlıkları (SafeTensors)"),
    ("Model weights (GGUF)", "Model ağırlıkları (GGUF)"),
    ("Model (ONNX)", "Model dosyası (ONNX)"),
    ("Checkpoint — counted, never opened", "Kontrol noktası — sayılır, asla açılmaz"),
    ("Weight file index", "Ağırlık dosyası dizini"),
    ("Adapter settings", "Adaptör ayarları"),
    ("Model settings", "Model ayarları"),
    ("Tokenizer settings", "Belirteçleyici ayarları"),
    ("Training history", "Eğitim geçmişi"),
    ("Training settings", "Eğitim ayarları"),
    ("Training log", "Eğitim günlüğü"),
    ("Software dependency list", "Yazılım bağımlılık listesi"),
    ("Deployment settings", "Dağıtım ayarları"),
    ("Serving settings", "Sunum ayarları"),
    ("Document search index", "Belge arama dizini"),
    ("Retrieval records", "Getirme kayıtları"),
    ("Model description", "Model açıklaması"),
    ("Other settings file", "Diğer ayar dosyası"),

    // ---- dialog titles -----------------------------------------------------
    ("Where should the vendor folder go?", "Tedarikçi klasörü nereye kaydedilsin?"),
    ("Open the file the vendor sent back", "Tedarikçinin gönderdiği dosyayı açın"),
    ("Instructions saved to {}", "Yönerge şuraya kaydedildi: {}"),
    (
        "The report also notes {} thing(s) this scan could not see. Those are limits of the scan itself.",
        "Rapor ayrıca bu taramanın göremediği {} şeyi not eder. Bunlar taramanın kendi sınırlarıdır.",
    ),

    // ---- help screen and band names ----------------------------------------
    (
        "How to use this",
        "Bu nasıl kullanılır",
    ),
    (
        "How to use Cladeon",
        "Cladeon nasıl kullanılır",
    ),
    (
        "Someone tells you they built their own AI. You would like to know whether that is what their files actually show.",
        "Birileri size kendi yapay zekâlarını kurduklarını söylüyor. Dosyalarının gerçekten bunu gösterip göstermediğini bilmek istiyorsunuz.",
    ),
    (
        "1.  Open a case",
        "1.  Dosya açın",
    ),
    (
        "Press \"Start a new check\" and answer the one question: what are they saying they built?",
        "\"Yeni bir denetim başlat\" düğmesine basın ve tek soruyu yanıtlayın: ne kurduklarını söylüyorlar?",
    ),
    (
        "Cladeon makes a folder named after the case. It holds the request and the small program they run.",
        "Cladeon, dosya numarasıyla adlandırılmış bir klasör oluşturur. İçinde istek ve onların çalıştıracağı küçük program bulunur.",
    ),
    (
        "2.  Send it to them",
        "2.  Onlara gönderin",
    ),
    (
        "Right-click the folder, choose Send to, then Compressed (zipped) folder. Attach that to an e-mail.",
        "Klasöre sağ tıklayın, Gönder seçeneğini, ardından Sıkıştırılmış klasör seçeneğini seçin. Onu bir e-postaya ekleyin.",
    ),
    (
        "They need no account, no internet connection and no administrator. They open one program and follow five screens.",
        "Hesaba, internet bağlantısına veya yönetici iznine ihtiyaçları yoktur. Tek bir program açar ve beş ekranı izlerler.",
    ),
    (
        "3.  Read what comes back",
        "3.  Geri geleni okuyun",
    ),
    (
        "They reply with one file ending in .clade  Press \"Open a file a vendor sent back\" and choose it.",
        "Size .clade uzantılı tek bir dosya gönderirler. \"Tedarikçinin gönderdiği dosyayı aç\" düğmesine basıp onu seçin.",
    ),
    (
        "What the report tells you",
        "Raporun size söyledikleri",
    ),
    (
        "There is no single score. Five separate questions are answered, and a good answer to one is never allowed to speak for the others.",
        "Tek bir puan yoktur. Beş ayrı soru yanıtlanır ve birine verilen iyi bir yanıtın diğerleri adına konuşmasına asla izin verilmez.",
    ),
    (
        "Whether anything was edited after they made it.",
        "Oluşturulduktan sonra bir şeyin düzenlenip düzenlenmediği.",
    ),
    (
        "Whether it is tied to the case you opened, not another one.",
        "Açtığınız dosyaya mı, yoksa başka birine mi bağlı olduğu.",
    ),
    (
        "Whether the printed report was re-exported or copied.",
        "Basılı raporun yeniden dışa aktarılıp aktarılmadığı veya kopyalanıp kopyalanmadığı.",
    ),
    (
        "Whether parts were left out. Leaving things out is allowed.",
        "Bazı bölümlerin dışarıda bırakılıp bırakılmadığı. Bir şeyi dışarıda bırakmak serbesttir.",
    ),
    (
        "Do the files fit the claim?",
        "Dosyalar iddiaya uyuyor mu?",
    ),
    (
        "The actual finding.",
        "Asıl bulgu budur.",
    ),
    (
        "What the finding can say",
        "Bulgunun söyleyebilecekleri",
    ),
    (
        "Two things worth knowing",
        "Bilinmesi gereken iki şey",
    ),
    (
        "If it says the files do not fit",
        "Dosyalar uymuyor diyorsa",
    ),
    (
        "It means the files disagree with the claim, within what was shown. It is a reason to ask a follow-up question. It is not a statement about anyone's honesty, and Cladeon does not make one.",
        "Bu, gösterilenler çerçevesinde dosyaların iddiayla uyuşmadığı anlamına gelir. Ek bir soru sormak için bir gerekçedir. Kimsenin dürüstlüğü hakkında bir yargı değildir ve Cladeon böyle bir yargıda bulunmaz.",
    ),
    (
        "Questions people ask",
        "Sıkça sorulan sorular",
    ),
    (
        "Does it upload anything?",
        "Herhangi bir şey yükler mi?",
    ),
    (
        "No. Neither program opens a network connection.",
        "Hayır. İki program da ağ bağlantısı açmaz.",
    ),
    (
        "Will it slow their machine down?",
        "Bilgisayarlarını yavaşlatır mı?",
    ),
    (
        "It reads file headers and checksums. A model folder takes minutes. A folder with hundreds of thousands of small files takes much longer, because Windows checks each file as it is opened.",
        "Dosya başlıklarını ve sağlama toplamlarını okur. Bir model klasörü dakikalar sürer. Yüz binlerce küçük dosya içeren bir klasör çok daha uzun sürer, çünkü Windows her dosyayı açılırken denetler.",
    ),
    (
        "What if they will not show something?",
        "Bir şeyi göstermek istemezlerse ne olur?",
    ),
    (
        "They can exclude it. The report records that a folder was excluded, never what was in it.",
        "Onu hariç tutabilirler. Rapor, bir klasörün hariç tutulduğunu kaydeder; içinde ne olduğunu asla kaydetmez.",
    ),
    (
        "Can they edit the report?",
        "Raporu düzenleyebilirler mi?",
    ),
    (
        "They can edit the file, but the checks stop matching and Cladeon says so.",
        "Dosyayı düzenleyebilirler, ancak kontroller tutmaz ve Cladeon bunu bildirir.",
    ),
    (
        "Is a screenshot enough?",
        "Ekran görüntüsü yeterli mi?",
    ),
    (
        "No. It must be the .clade file itself, unchanged.",
        "Hayır. Dosyanın kendisi, .clade uzantılı hâliyle ve değiştirilmeden gönderilmelidir.",
    ),
    (
        "Does it settle whether they trained a model?",
        "Bir model eğitip eğitmediklerini kesin olarak belirler mi?",
    ),
    (
        "No, and it does not claim to. Read the line at the foot of every screen.",
        "Hayır ve böyle bir iddiada da bulunmaz. Her ekranın altındaki satırı okuyun.",
    ),
    (
        "Corroborated",
        "Doğrulandı",
    ),
    (
        "Strongly consistent",
        "Güçlü biçimde tutarlı",
    ),
    (
        "Weakly consistent",
        "Zayıf biçimde tutarlı",
    ),
    (
        "Partially supported",
        "Kısmen destekleniyor",
    ),
    (
        "Not enough evidence",
        "Yeterli kanıt yok",
    ),
    (
        "The files do not fit",
        "Dosyalar uymuyor",
    ),
    (
        "Nothing of that kind was sent",
        "Bu türde bir şey gönderilmedi",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_english_string_has_two_translations() {
        // One flat table exists precisely so that a sentence appearing on two screens
        // cannot acquire two Turkish renderings that drift apart.
        let mut seen: Vec<&str> = Vec::new();
        for (en, _) in TR {
            assert!(!seen.contains(en), "`{en}` is translated twice");
            seen.push(en);
        }
    }

    #[test]
    fn nothing_is_left_in_english() {
        // A copied-but-untranslated row is the easiest mistake to make and the
        // hardest to see, because the interface looks finished.
        for (en, tr) in TR {
            assert_ne!(en, tr, "`{en}` was copied, not translated");
            assert!(!tr.trim().is_empty(), "`{en}` has an empty translation");
        }
    }

    #[test]
    fn english_is_returned_untouched() {
        assert_eq!(t(Lang::En, "Start a new check"), "Start a new check");
        assert_eq!(t(Lang::En, "not in the table at all"), "not in the table at all");
    }

    #[test]
    fn an_unknown_string_falls_back_rather_than_showing_a_blank() {
        // Better a sentence in the wrong language than an empty label. The coverage
        // test below is what stops this being a way to ship gaps.
        assert_eq!(t(Lang::Tr, "not in the table at all"), "not in the table at all");
    }

    #[test]
    fn turkish_is_reachable_and_uses_its_own_alphabet() {
        assert_eq!(t(Lang::Tr, "Back"), "Geri");
        let joined: String = TR.iter().map(|(_, tr)| *tr).collect::<Vec<_>>().join(" ");
        for ch in ['ç', 'ğ', 'ı', 'İ', 'ö', 'ş', 'ü'] {
            assert!(joined.contains(ch), "no `{ch}` anywhere: the diacritics were stripped");
        }
    }

    #[test]
    fn the_required_statement_resolves_from_the_constant_itself() {
        // Transcribed by hand into the table, so the risk is a near-miss that looks
        // right in review and silently falls back to English at runtime. Looking it
        // up through the constant is the only check that catches that.
        let tr = t(Lang::Tr, cl_core::REQUIRED_STATEMENT);
        assert_ne!(
            tr, cl_core::REQUIRED_STATEMENT,
            "the table key no longer matches REQUIRED_STATEMENT character for character"
        );
        assert!(tr.contains("Aşama-1"), "{tr}");
    }

    #[test]
    fn language_tags_round_trip() {
        for l in Lang::ALL {
            assert_eq!(Lang::parse(l.as_str()), Some(*l));
            assert!(!l.endonym().is_empty());
        }
        assert_eq!(Lang::parse("TR"), Some(Lang::Tr));
        assert_eq!(Lang::parse("  tr  "), Some(Lang::Tr));
        assert_eq!(Lang::parse("de"), None);
    }

    #[test]
    fn a_language_names_itself_in_its_own_words() {
        // Someone looking for Turkish is looking for "Türkçe"; a menu offering them
        // "Turkish" is a menu they cannot read.
        assert_eq!(Lang::Tr.endonym(), "Türkçe");
    }

    #[test]
    fn the_preference_is_stored_per_user_and_not_beside_the_executable() {
        let p = settings_path().expect("a settings path must resolve");
        assert!(p.is_absolute());
        let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
        assert_ne!(p.parent(), Some(exe_dir.as_path()));
    }

    #[test]
    fn a_saved_choice_round_trips_through_the_file_format() {
        // The file holds the tag and nothing else, so this is the whole format.
        for l in Lang::ALL {
            assert_eq!(Lang::parse(l.as_str()), Some(*l));
        }
    }

    #[test]
    fn from_os_never_panics_and_defaults_to_english() {
        let _ = Lang::from_os();
        assert_eq!(Lang::parse("").unwrap_or_default(), Lang::En);
    }
}
