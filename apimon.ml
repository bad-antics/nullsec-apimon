(* NullSec APIMon - API Call Monitor
   OCaml security tool demonstrating:
   - Algebraic data types and pattern matching
   - Immutable data structures
   - Strong static typing
   - Functional programming paradigms
   - Module system for organization
   
   Author: bad-antics
   License: MIT *)

let version = "1.0.0"

(* ANSI Colors *)
module Color = struct
  let red = "\027[31m"
  let green = "\027[32m"
  let yellow = "\027[33m"
  let cyan = "\027[36m"
  let gray = "\027[90m"
  let reset = "\027[0m"
  
  let apply c s = c ^ s ^ reset
end

(* Severity levels *)
type severity =
  | Critical
  | High
  | Medium
  | Low
  | Info

let severity_to_string = function
  | Critical -> "CRITICAL"
  | High -> "HIGH"
  | Medium -> "MEDIUM"
  | Low -> "LOW"
  | Info -> "INFO"

let severity_color = function
  | Critical | High -> Color.red
  | Medium -> Color.yellow
  | Low -> Color.cyan
  | Info -> Color.gray

(* API categories *)
type api_category =
  | FileSystem
  | Registry
  | Network
  | Process
  | Memory
  | Crypto
  | System
  | Unknown

let category_to_string = function
  | FileSystem -> "FileSystem"
  | Registry -> "Registry"
  | Network -> "Network"
  | Process -> "Process"
  | Memory -> "Memory"
  | Crypto -> "Crypto"
  | System -> "System"
  | Unknown -> "Unknown"

(* API call record *)
type api_call = {
  timestamp : float;
  pid : int;
  tid : int;
  api_name : string;
  category : api_category;
  args : string list;
  return_value : string;
  success : bool;
}

(* Alert record *)
type alert = {
  severity : severity;
  message : string;
  api : api_call;
  rule_id : string;
}

(* Detection rules *)
type rule = {
  id : string;
  name : string;
  pattern : string;
  severity : severity;
  description : string;
}

(* Suspicious API patterns *)
let suspicious_rules = [
  (* Process injection *)
  { id = "INJ001"; name = "Process Injection"; pattern = "VirtualAllocEx";
    severity = Critical; description = "Remote memory allocation detected" };
  { id = "INJ002"; name = "Process Injection"; pattern = "WriteProcessMemory";
    severity = Critical; description = "Remote memory write detected" };
  { id = "INJ003"; name = "Process Injection"; pattern = "CreateRemoteThread";
    severity = Critical; description = "Remote thread creation detected" };
  { id = "INJ004"; name = "Process Injection"; pattern = "NtQueueApcThread";
    severity = Critical; description = "APC injection detected" };
  
  (* Credential theft *)
  { id = "CRED001"; name = "Credential Access"; pattern = "CredEnumerate";
    severity = High; description = "Credential enumeration" };
  { id = "CRED002"; name = "Credential Access"; pattern = "LsaRetrievePrivateData";
    severity = Critical; description = "LSA secret access" };
  { id = "CRED003"; name = "Credential Access"; pattern = "SamQueryInformationUser";
    severity = High; description = "SAM user query" };
  
  (* File system *)
  { id = "FILE001"; name = "Suspicious File"; pattern = "DeleteFile";
    severity = Medium; description = "File deletion" };
  { id = "FILE002"; name = "Shadow Copy"; pattern = "vssadmin";
    severity = High; description = "Volume shadow copy manipulation" };
  
  (* Network *)
  { id = "NET001"; name = "Network"; pattern = "connect";
    severity = Low; description = "Network connection" };
  { id = "NET002"; name = "Network"; pattern = "WSAConnect";
    severity = Low; description = "Winsock connection" };
  
  (* Anti-analysis *)
  { id = "ANTI001"; name = "Anti-Debug"; pattern = "IsDebuggerPresent";
    severity = High; description = "Debugger detection" };
  { id = "ANTI002"; name = "Anti-VM"; pattern = "CPUID";
    severity = Medium; description = "VM detection attempt" };
  
  (* Registry *)
  { id = "REG001"; name = "Persistence"; pattern = "RegSetValue";
    severity = Medium; description = "Registry modification" };
  { id = "REG002"; name = "Security"; pattern = "RegDeleteKey";
    severity = Medium; description = "Registry key deletion" };
]

(* Configuration *)
type config = {
  target_pid : int option;
  show_all : bool;
  json_output : bool;
  verbose : bool;
  filter_category : api_category option;
}

let default_config = {
  target_pid = None;
  show_all = false;
  json_output = false;
  verbose = false;
  filter_category = None;
}

(* Check if API matches any rule *)
let check_rules api =
  List.filter_map (fun rule ->
    if String.sub api.api_name 0 
       (min (String.length rule.pattern) (String.length api.api_name)) = 
       String.sub rule.pattern 0 
       (min (String.length rule.pattern) (String.length api.api_name))
    then Some { severity = rule.severity; 
                message = rule.description;
                api = api;
                rule_id = rule.id }
    else None
  ) suspicious_rules

(* Categorize API call *)
let categorize_api name =
  let name_lower = String.lowercase_ascii name in
  if String.length name_lower > 0 then
    match String.get name_lower 0 with
    | 'c' when String.sub name_lower 0 (min 6 (String.length name_lower)) = "create" -> Process
    | 'r' when String.sub name_lower 0 (min 3 (String.length name_lower)) = "reg" -> Registry
    | 'n' when String.sub name_lower 0 (min 2 (String.length name_lower)) = "nt" -> System
    | 'w' when String.sub name_lower 0 (min 3 (String.length name_lower)) = "wsa" -> Network
    | 'v' when String.sub name_lower 0 (min 7 (String.length name_lower)) = "virtual" -> Memory
    | 'c' when String.sub name_lower 0 (min 5 (String.length name_lower)) = "crypt" -> Crypto
    | _ -> 
      if String.length name_lower >= 4 && String.sub name_lower 0 4 = "file" then FileSystem
      else Unknown
  else Unknown

(* Print banner *)
let print_banner () =
  print_endline "";
  print_endline "╔══════════════════════════════════════════════════════════════════╗";
  print_endline "║            NullSec APIMon - API Call Monitor                     ║";
  print_endline "╚══════════════════════════════════════════════════════════════════╝";
  print_endline ""

(* Print usage *)
let print_usage () =
  print_banner ();
  print_endline "USAGE:";
  print_endline "    apimon [OPTIONS] [PID]";
  print_endline "";
  print_endline "OPTIONS:";
  print_endline "    -h, --help       Show this help";
  print_endline "    -a, --all        Show all API calls";
  print_endline "    -j, --json       JSON output";
  print_endline "    -v, --verbose    Verbose output";
  print_endline "    -c CATEGORY      Filter by category";
  print_endline "";
  print_endline "CATEGORIES:";
  print_endline "    FileSystem, Registry, Network, Process, Memory, Crypto, System";
  print_endline "";
  print_endline "EXAMPLES:";
  print_endline "    apimon 1234";
  print_endline "    apimon -a -c Network 1234";
  print_endline "    apimon -j 1234 > trace.json";
  print_endline "";
  print_endline "DETECTIONS:";
  print_endline "    - Process injection (VirtualAllocEx, WriteProcessMemory)";
  print_endline "    - Credential theft (CredEnumerate, LsaRetrievePrivateData)";
  print_endline "    - Anti-analysis (IsDebuggerPresent, CPUID)";
  print_endline "    - Persistence (Registry modifications)"

(* Format timestamp *)
let format_timestamp ts =
  let tm = Unix.localtime ts in
  Printf.sprintf "%02d:%02d:%02d.%03d"
    tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec
    (int_of_float ((ts -. floor ts) *. 1000.0))

(* Print API call *)
let print_api_call api =
  let cat_str = category_to_string api.category in
  let status = if api.success then Color.apply Color.green "OK" 
               else Color.apply Color.red "FAIL" in
  Printf.printf "%s [%d:%d] %s %-20s %s -> %s\n"
    (format_timestamp api.timestamp)
    api.pid api.tid
    (Color.apply Color.cyan (Printf.sprintf "%-10s" cat_str))
    api.api_name
    (String.concat ", " api.args)
    status

(* Print alert *)
let print_alert alert =
  let sev_str = severity_to_string alert.severity in
  let sev_color = severity_color alert.severity in
  Printf.printf "%s [%s] %s: %s (%s)\n"
    (Color.apply sev_color (Printf.sprintf "[%-8s]" sev_str))
    alert.rule_id
    alert.api.api_name
    alert.message
    (String.concat ", " alert.api.args)

(* Simulate some API calls for demo *)
let simulate_calls () =
  let base_time = Unix.gettimeofday () in
  [
    { timestamp = base_time;
      pid = 1234; tid = 5678;
      api_name = "CreateFile";
      category = FileSystem;
      args = ["C:\\Windows\\System32\\kernel32.dll"; "GENERIC_READ"];
      return_value = "0x1234"; success = true };
    { timestamp = base_time +. 0.001;
      pid = 1234; tid = 5678;
      api_name = "VirtualAllocEx";
      category = Memory;
      args = ["0x5678"; "4096"; "MEM_COMMIT|MEM_RESERVE"];
      return_value = "0x00400000"; success = true };
    { timestamp = base_time +. 0.002;
      pid = 1234; tid = 5678;
      api_name = "WriteProcessMemory";
      category = Memory;
      args = ["0x5678"; "0x00400000"; "4096 bytes"];
      return_value = "TRUE"; success = true };
    { timestamp = base_time +. 0.003;
      pid = 1234; tid = 5678;
      api_name = "CreateRemoteThread";
      category = Process;
      args = ["0x5678"; "0x00400000"];
      return_value = "0x1111"; success = true };
    { timestamp = base_time +. 0.004;
      pid = 1234; tid = 5678;
      api_name = "IsDebuggerPresent";
      category = System;
      args = [];
      return_value = "FALSE"; success = true };
    { timestamp = base_time +. 0.005;
      pid = 1234; tid = 5678;
      api_name = "RegSetValueExA";
      category = Registry;
      args = ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"; "Updater"];
      return_value = "0"; success = true };
  ]

(* Run monitor *)
let run_monitor cfg =
  print_endline (Color.apply Color.cyan "Monitoring API calls...");
  print_endline "(Demo mode - simulated calls)\n";
  
  let calls = simulate_calls () in
  let all_alerts = ref [] in
  
  (* Process each call *)
  List.iter (fun call ->
    if cfg.show_all then print_api_call call;
    
    let alerts = check_rules call in
    all_alerts := !all_alerts @ alerts;
    
    List.iter print_alert alerts
  ) calls;
  
  (* Summary *)
  print_endline "";
  print_endline (Color.apply Color.gray "═══════════════════════════════════════════");
  print_endline "";
  print_endline "Summary:";
  Printf.printf "  Total calls:  %d\n" (List.length calls);
  Printf.printf "  Alerts:       %d\n" (List.length !all_alerts);
  
  let critical = List.filter (fun a -> a.severity = Critical) !all_alerts in
  let high = List.filter (fun a -> a.severity = High) !all_alerts in
  
  Printf.printf "  %s %d\n" (Color.apply Color.red "Critical:") (List.length critical);
  Printf.printf "  %s %d\n" (Color.apply Color.red "High:") (List.length high)

(* Parse args *)
let rec parse_args args cfg =
  match args with
  | [] -> cfg
  | "-h" :: _ | "--help" :: _ -> { cfg with target_pid = None }
  | "-a" :: rest | "--all" :: rest -> parse_args rest { cfg with show_all = true }
  | "-j" :: rest | "--json" :: rest -> parse_args rest { cfg with json_output = true }
  | "-v" :: rest | "--verbose" :: rest -> parse_args rest { cfg with verbose = true }
  | "-c" :: cat :: rest -> 
    let category = match String.lowercase_ascii cat with
      | "filesystem" -> Some FileSystem
      | "registry" -> Some Registry
      | "network" -> Some Network
      | "process" -> Some Process
      | "memory" -> Some Memory
      | "crypto" -> Some Crypto
      | "system" -> Some System
      | _ -> None
    in parse_args rest { cfg with filter_category = category }
  | pid :: rest ->
    (try
      parse_args rest { cfg with target_pid = Some (int_of_string pid) }
    with Failure _ -> parse_args rest cfg)

(* Main entry point *)
let () =
  let args = Array.to_list Sys.argv |> List.tl in
  let cfg = parse_args args default_config in
  
  match cfg.target_pid with
  | None -> print_usage ()
  | Some _ ->
    if not cfg.json_output then print_banner ();
    run_monitor cfg
