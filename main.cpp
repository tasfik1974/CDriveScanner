#define NOMINMAX
#include "Include.h"

static std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring w(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &w[0], sz);
    return w;
}
static std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string s(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &s[0], sz, nullptr, nullptr);
    return s;
}

YR_RULES*   g_compiled_rules  = nullptr;
bool        scanMyYara        = false;
bool        scanOwnYara       = false;
bool        scanForReplaces   = false;
bool        scanForDLLsOnly   = false;

std::mutex  cacheMutex;
std::mutex  consoleMutex;
std::mutex  replaceMutex;

void process_paths_worker(const std::vector<std::string>& paths,
                           size_t start_index, size_t end_index,
                           HANDLE hConsole)
{
    for (size_t i = start_index; i < end_index; ++i) {
        const std::string& path = paths[i];
        FileInfo info;
        bool found_in_cache = false;
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = fileCache.find(path);
            if (it != fileCache.end()) { info = it->second; found_in_cache = true; }
        }
        if (!found_in_cache) {
            info.exists      = file_exists(path);
            info.isDirectory = info.exists && is_directory(path);
            info.isValidMZ   = info.exists && !info.isDirectory && isMZFile(path);

            if (info.exists && info.isValidMZ) {
                info.signatureStatus = getDigitalSignature(path);
                if (info.signatureStatus != "Signed" && (scanMyYara || scanOwnYara)) {
                    if (!iequals(path, getOwnPath()))
                        scan_with_yara(path, info.matched_rules, g_compiled_rules);
                }
            }
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                fileCache.insert_or_assign(path, info);
            }
        }

        {
            std::lock_guard<std::mutex> lock(consoleMutex);
            if (!info.exists || info.isDirectory) continue;

            if (info.isValidMZ) {
                if (info.signatureStatus == "Signed") {
                    SetConsoleTextAttribute(hConsole, 2);
                    std::cout << "[Signed]         ";
                } else if (info.signatureStatus == "Cheat Signature") {
                    SetConsoleTextAttribute(hConsole, 12);
                    std::cout << "[Cheat Sig]      ";
                } else if (info.signatureStatus == "Fake Signature") {
                    SetConsoleTextAttribute(hConsole, 12);
                    std::cout << "[Fake Sig]       ";
                } else {
                    SetConsoleTextAttribute(hConsole, 6);
                    std::cout << "[Not Signed]     ";
                }
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                if (!info.matched_rules.empty()) {
                    SetConsoleTextAttribute(hConsole, 12);
                    for (auto& r : info.matched_rules) std::cout << "  [YARA:" << r << "]";
                    SetConsoleTextAttribute(hConsole, 7);
                }
                if (scanForReplaces) {
                    std::string filename;
                    size_t pos = path.find_last_of("\\/");
                    filename = (pos != std::string::npos) ? path.substr(pos + 1) : path;
                    std::lock_guard<std::mutex> repl(replaceMutex);
                    FindReplace(filename);
                }
                std::cout << "\n";
            } else {
                SetConsoleTextAttribute(hConsole, 8);
                std::cout << "[Not MZ]         ";
                SetConsoleTextAttribute(hConsole, 7);
                auto wpath = utf8_to_wstring(path);
                WriteConsoleW(hConsole, wpath.c_str(), (DWORD)wpath.size(), nullptr, nullptr);
                std::cout << "\n";
            }
        }
    }
}

static void printBanner(HANDLE hConsole) {
    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "\n";
    std::cout << "  +======================================================+\n";
    std::cout << "  |         C:\\ Drive Scanner  -  by espouken             |\n";
    std::cout << "  |   Scans every .exe / .dll / .sys on C: drive          |\n";
    std::cout << "  |   Checks signatures + optional YARA rules             |\n";
    std::cout << "  +======================================================+\n";
    std::cout << "\n";
    SetConsoleTextAttribute(hConsole, 7);
}

static void writeReport(HANDLE hConsole) {
    struct DetectEntry {
        std::string path;
        std::string status;
        std::vector<std::string> yaraHits;
    };

    std::vector<DetectEntry> signed_files, unsigned_files, cheat_files, fake_files, yara_files;

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        for (auto& kv : fileCache) {
            if (!kv.second.exists || kv.second.isDirectory || !kv.second.isValidMZ) continue;
            DetectEntry e{ kv.first, kv.second.signatureStatus, kv.second.matched_rules };
            if (!e.yaraHits.empty())                 yara_files.push_back(e);
            if      (e.status == "Signed")           signed_files.push_back(e);
            else if (e.status == "Cheat Signature")  cheat_files.push_back(e);
            else if (e.status == "Fake Signature")   fake_files.push_back(e);
            else                                     unsigned_files.push_back(e);
        }
    }

    auto bySig = [](const DetectEntry& a, const DetectEntry& b){ return a.path < b.path; };
    std::sort(signed_files.begin(),   signed_files.end(),   bySig);
    std::sort(unsigned_files.begin(), unsigned_files.end(), bySig);
    std::sort(cheat_files.begin(),    cheat_files.end(),    bySig);
    std::sort(fake_files.begin(),     fake_files.end(),     bySig);
    std::sort(yara_files.begin(),     yara_files.end(),     bySig);

    std::string reportPath = getOwnDirectory() + "detection_report.txt";
    std::ofstream rep(reportPath);
    if (!rep.is_open()) { reportPath = "detection_report.txt"; rep.open(reportPath); }

    std::string div(72, '=');

    auto sec = [&](const std::string& title, const std::vector<DetectEntry>& vec) {
        if (vec.empty()) return;
        rep << div << "\n";
        rep << "  " << title << "  (" << vec.size() << " files)\n";
        rep << div << "\n";
        for (auto& e : vec) {
            rep << "  [" << e.status << "]  " << e.path;
            if (!e.yaraHits.empty()) {
                rep << "  --> YARA: ";
                for (auto& r : e.yaraHits) rep << "[" << r << "]";
            }
            rep << "\n";
        }
        rep << "\n";
    };

    rep << div << "\n";
    rep << "  C:\\ Drive Scanner  -  Detection Report\n";
    rep << div << "\n";
    rep << "  Signed          : " << signed_files.size()   << "\n";
    rep << "  Not Signed      : " << unsigned_files.size() << "\n";
    rep << "  Cheat Signature : " << cheat_files.size()    << "\n";
    rep << "  Fake Signature  : " << fake_files.size()     << "\n";
    rep << "  YARA Hits       : " << yara_files.size()     << "\n";
    rep << div << "\n\n";

    sec("CHEAT SIGNATURE  [HIGH RISK]",  cheat_files);
    sec("FAKE SIGNATURE   [HIGH RISK]",  fake_files);
    sec("YARA RULE HITS   [SUSPICIOUS]", yara_files);
    sec("NOT SIGNED",                    unsigned_files);
    sec("SIGNED  (clean)",               signed_files);
    rep.close();

    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "\n  +======================================+\n";
    std::cout <<   "  |        DETECTION SUMMARY             |\n";
    std::cout <<   "  +======================================+\n";
    SetConsoleTextAttribute(hConsole, 2);
    std::cout << "  Signed          : " << signed_files.size()   << "\n";
    SetConsoleTextAttribute(hConsole, 6);
    std::cout << "  Not Signed      : " << unsigned_files.size() << "\n";
    SetConsoleTextAttribute(hConsole, 12);
    std::cout << "  Cheat Signature : " << cheat_files.size()    << "\n";
    std::cout << "  Fake Signature  : " << fake_files.size()     << "\n";
    SetConsoleTextAttribute(hConsole, 13);
    std::cout << "  YARA Hits       : " << yara_files.size()     << "\n";
    SetConsoleTextAttribute(hConsole, 14);
    std::cout << "\n  Report saved to: " << reportPath << "\n\n";
    SetConsoleTextAttribute(hConsole, 7);

    std::string cmd = "start \"\" \"" + reportPath + "\"";
    std::system(cmd.c_str());
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleA("C:\\ Drive Scanner  -  made by espouken");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    printBanner(hConsole);

    if (!privilege("SeDebugPrivilege")) {
        SetConsoleTextAttribute(hConsole, 12);
        std::cout << "  [!] Failed to acquire SeDebugPrivilege.\n"
                  << "      Please run as Administrator.\n";
        SetConsoleTextAttribute(hConsole, 7);
        std::cout << "\n  Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    auto ask = [&](const std::string& q) -> bool {
        SetConsoleTextAttribute(hConsole, 14);
        std::cout << "  " << q << " (Y/N): ";
        SetConsoleTextAttribute(hConsole, 7);
        std::string in; std::getline(std::cin, in);
        return (in == "Y" || in == "y");
    };

    scanMyYara      = ask("Scan with built-in YARA rules?");
    scanOwnYara     = ask("Scan with your own .yar files?");
    scanForReplaces = ask("Check for file replacements?");
    std::cout << "\n";

    if (yr_initialize() != ERROR_SUCCESS) {
        SetConsoleTextAttribute(hConsole, 12);
        std::cerr << "  [!] Failed to initialize YARA.\n";
        SetConsoleTextAttribute(hConsole, 7);
        std::cin.get();
        return 1;
    }

    if (scanMyYara)  initializeGenericRules();
    if (scanOwnYara) initializateCustomRules();

    if (scanMyYara || scanOwnYara) {
        YR_COMPILER* compiler = nullptr;
        yr_compiler_create(&compiler);
        yr_compiler_set_callback(compiler, compiler_error_callback, nullptr);
        for (auto& r : genericRules)
            yr_compiler_add_string(compiler, r.rule.c_str(), r.name.c_str());
        yr_compiler_get_rules(compiler, &g_compiled_rules);
        yr_compiler_destroy(compiler);
        SetConsoleTextAttribute(hConsole, 10);
        std::cout << "  [+] YARA rules compiled OK.\n\n";
        SetConsoleTextAttribute(hConsole, 7);
    }

    if (scanForReplaces) {
        initReplaceParser();
        PreProcessReplacements(replaceParserDir + "\\replaces.txt");
    }

    auto paths = getAllTargetPaths();
    if (paths.empty()) {
        SetConsoleTextAttribute(hConsole, 12);
        std::cout << "  [!] No .exe/.dll/.sys files found on C:\\\n";
        SetConsoleTextAttribute(hConsole, 7);
        if (g_compiled_rules) yr_rules_destroy(g_compiled_rules);
        yr_finalize();
        std::cin.get();
        return 1;
    }

    unsigned num_threads = std::max(1u, std::thread::hardware_concurrency());
    size_t   total       = paths.size();
    size_t   per         = (total + num_threads - 1) / num_threads;

    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "  Processing " << total << " files  |  " << num_threads << " threads\n\n";
    SetConsoleTextAttribute(hConsole, 7);

    std::vector<std::thread> workers;
    size_t idx = 0;
    for (unsigned t = 0; t < num_threads && idx < total; ++t) {
        size_t end = std::min(idx + per, total);
        workers.emplace_back(process_paths_worker, std::cref(paths), idx, end, hConsole);
        idx = end;
    }
    for (auto& w : workers) if (w.joinable()) w.join();

    SetConsoleTextAttribute(hConsole, 10);
    std::cout << "\n  [+] All files processed.\n";
    SetConsoleTextAttribute(hConsole, 7);

    if (scanForReplaces) {
        DestroyReplaceParser();
        WriteAllReplacementsToFileAndPrintSummary();
    }

    writeReport(hConsole);

    if (g_compiled_rules) { yr_rules_destroy(g_compiled_rules); g_compiled_rules = nullptr; }
    yr_finalize();

    SetConsoleTextAttribute(hConsole, 11);
    std::cout << "  --------------- Scan Complete ---------------\n";
    SetConsoleTextAttribute(hConsole, 7);
    std::cout << "  Press Enter to exit...";
    std::cin.get();
    return 0;
}
