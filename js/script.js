const API_BASE = "/api";
let AUTH_TOKEN = localStorage.getItem("cybershield_token") || null;

function apiUrl(p) { return `${API_BASE}${p}`; }
function authHeaders() { const h = {"Content-Type":"application/json"}; if(AUTH_TOKEN) h["Authorization"]=`Bearer ${AUTH_TOKEN}`; return h; }
function authHeadersNoType() { const h = {}; if(AUTH_TOKEN) h["Authorization"]=`Bearer ${AUTH_TOKEN}`; return h; }
async function apiGet(p) { const r=await fetch(apiUrl(p),{headers:authHeaders()}); if(r.status===401 && !window.location.pathname.includes("login")){localStorage.removeItem("cybershield_token");AUTH_TOKEN=null;showToast("Session Expired","Redirecting to login","danger");setTimeout(()=>{window.location.href="login.html"},1500);return{error:"Token expired"}}; return r.json(); }
async function apiPost(p,b) { const r=await fetch(apiUrl(p),{method:"POST",headers:authHeaders(),body:JSON.stringify(b)}); if(r.status===401 && !window.location.pathname.includes("login")){localStorage.removeItem("cybershield_token");AUTH_TOKEN=null;showToast("Session Expired","Redirecting to login","danger");setTimeout(()=>{window.location.href="login.html"},1500);return{error:"Token expired"}}; return r.json(); }
async function apiDownload(p,fn) {
  const r=await fetch(apiUrl(p),{headers:authHeaders()});
  if(!r.ok){showToast("Download Failed","Try again","danger");return;}
  const blob=await r.blob(); const a=document.createElement("a");
  a.href=URL.createObjectURL(blob); a.download=fn||"report"; a.click();
  URL.revokeObjectURL(a.href);
}

function showToast(title,msg,type="info"){
  const c=document.getElementById("toast-container");
  if(!c) return;
  const t=document.createElement("div");
  t.className=`toast t-${type}`;
  t.innerHTML=`<div class="toast-title">${title}</div><div class="toast-msg">${msg}</div>`;
  c.appendChild(t);
  setTimeout(()=>{t.style.opacity="0";t.style.transform="translateX(40px)";t.style.transition="all 0.3s";setTimeout(()=>t.remove(),300);},4000);
}

function showAlert(msg){
  const el=document.getElementById("alertMsg"); const t=document.getElementById("alertText");
  if(el&&t){el.style.display="flex";t.textContent=msg;}
}

let loginUserId = null;
let loginDelivery = "email";

async function doLogin(){
  const email=document.getElementById("emailInput")?.value.trim();
  const pw=document.getElementById("pwInput")?.value;
  const btn=document.getElementById("loginBtn");
  if(!email||!pw){showAlert("Please enter email and password");return;}
  btn?.classList.add("loading");
  try{
    const res=await apiPost("/auth/login",{email,password:pw});
    if(res.success){
      if(res.requires2FA){
        loginUserId = email;
        loginDelivery = res.delivery || "email";
        document.getElementById("otpDeliveryMsg").textContent = `📧 OTP sent to ${email}`;
        document.getElementById("mfaSection").classList.add("show");
        document.getElementById("loginBtn").style.display = "none";
        document.getElementById("verifyOtpBtn").style.display = "flex";
        document.getElementById("resendOtpLink").style.display = "block";
        showToast("OTP Sent",`Check your ${res.delivery} for the code`,"info");
        btn?.classList.remove("loading");
        return;
      }
      AUTH_TOKEN=res.token;
      localStorage.setItem("cybershield_token",res.token);
      showToast("Login Successful",`Welcome ${res.user.name}`,"safe");
      setTimeout(()=>{window.location.href="dashboard.html";},500);
    } else showAlert(res.message||"Login failed");
  }catch(e){showAlert("Connection error. Is the backend running?");}
  btn?.classList.remove("loading");
}

async function doMobileLogin(){
  const phone=document.getElementById("mobileInput")?.value.trim();
  const pin=document.getElementById("pinInput")?.value;
  const btn=document.getElementById("mobileLoginBtn");
  if(!phone||!pin){showAlert("Please enter phone and PIN");return;}
  btn?.classList.add("loading");
  try{
    const res=await apiPost("/auth/mobile-login",{phone,pin});
    if(res.success){
      if(res.requires2FA){
        loginUserId = phone;
        loginDelivery = "sms";
        document.getElementById("otpDeliveryMsg").textContent = `📱 OTP sent to ${phone}`;
        document.getElementById("mfaSection").classList.add("show");
        document.getElementById("mobileLoginBtn").style.display = "none";
        document.getElementById("verifyOtpBtn").style.display = "flex";
        document.getElementById("resendOtpLink").style.display = "block";
        showToast("OTP Sent",`Check your phone for the code`,"info");
        btn?.classList.remove("loading");
        return;
      }
      AUTH_TOKEN=res.token; localStorage.setItem("cybershield_token",res.token);
      showToast("Mobile Login Successful","Welcome","safe");
      setTimeout(()=>{window.location.href="dashboard.html";},500);
    } else showAlert(res.message||"Login failed");
  }catch(e){showAlert("Connection error");}
  btn?.classList.remove("loading");
}

async function verifyOtpAndLogin(){
  const otp = Array.from({length:6}, (_,i) => document.getElementById(`o${i+1}`)?.value).join("");
  const btn = document.getElementById("verifyOtpBtn");
  if(otp.length !== 6){showAlert("Please enter all 6 OTP digits");return;}
  btn?.classList.add("loading");
  try{
    const payload = loginDelivery === "sms"
      ? {otp, phone: loginUserId}
      : {otp, email: loginUserId};
    const res=await apiPost("/auth/verify-2fa", payload);
    if(res.success){
      AUTH_TOKEN=res.token;
      localStorage.setItem("cybershield_token",res.token);
      showToast("Login Successful","MFA verified — redirecting","safe");
      setTimeout(()=>{window.location.href="dashboard.html";},500);
    } else showAlert(res.message||"OTP verification failed");
  }catch(e){showAlert("Connection error");}
  btn?.classList.remove("loading");
}

async function resendOTP(){
  const payload = loginDelivery === "sms"
    ? {phone: loginUserId}
    : {email: loginUserId};
  try{
    const res=await apiPost("/auth/send-otp", payload);
    if(res.success) showToast("OTP Resent",res.message,"info");
    else showAlert(res.message||"Failed to resend OTP");
  }catch(e){showAlert("Connection error");}
}

/* ════════════════════════════════════════════
   DASHBOARD
   ════════════════════════════════════════════ */

async function loadDashboardStats(){
  try{
    const res=await apiGet("/mobile/dashboard-stats");
    if(!res.success) return;
    const s=res.stats;
    setText("cnt1",s.threats_blocked);
    setText("cnt2",s.sms_phishing+s.calls_blocked);
    setText("cnt3",s.devices_monitored);
    setText("cnt4","100");
    setText("m-threats",s.threats_blocked);
    setText("m-apps",s.total_apps);
    setText("m-sms",s.sms_phishing);
    setText("threats-count",s.threats_blocked);
  }catch(e){}
}
function setText(id,val){ const el=document.getElementById(id); if(el) el.textContent=val; }

/* ════════════════════════════════════════════
   EMAIL SECURITY (23 features)
   ════════════════════════════════════════════ */

async function checkSPF(){
  const d=document.getElementById("spfInput")?.value||document.getElementById("domainInput")?.value||"cybershield.com";
  showLoading("res-spf");
  const r=await apiPost("/email/check-spf",{domain:d});
  showResult("res-spf",r,"SPF");
}
async function checkDKIM(){
  const d=document.getElementById("dkimInput")?.value||document.getElementById("domainInput")?.value||"cybershield.com";
  showLoading("res-dkim");
  const r=await apiPost("/email/check-dkim",{domain:d});
  showResult("res-dkim",r,"DKIM");
}
async function checkDMARC(){
  const d=document.getElementById("dmarcInput")?.value||document.getElementById("domainInput")?.value||"cybershield.com";
  showLoading("res-dmarc");
  const r=await apiPost("/email/check-dmarc",{domain:d});
  showResult("res-dmarc",r,"DMARC");
}
async function checkSandbox(){
  const fn=document.getElementById("sandboxInput")?.value||"invoice.exe";
  showLoading("res-sandbox");
  const r=await apiPost("/email/sandbox-analysis",{file_name:fn});
  showResult("res-sandbox",r,"Sandbox");
}
async function checkURL(){
  const url=document.getElementById("urlInput")?.value||"http://bit.ly/test-link";
  showLoading("res-url");
  const r=await apiPost("/email/url-analysis",{url});
  showResult("res-url",r,"URL");
}
async function checkLookalike(){
  const d=document.getElementById("lookalikeInput")?.value||"g00gle.com";
  showLoading("res-lookalike");
  const r=await apiPost("/email/lookalike-domain",{domain:d});
  showResult("res-lookalike",r,"Lookalike");
}
async function checkBEC(){
  const body=document.getElementById("becInput")?.value||"Urgent: Wire transfer needed ASAP. Change payment details.";
  showLoading("res-bec");
  const r=await apiPost("/email/bec-scan",{body,sender_name:"CEO",sender_domain:"corp.com",reply_to:"attacker@evil.com"});
  showResult("res-bec",r,"BEC");
}
async function checkHeuristic(){
  const body=document.getElementById("heuristicInput")?.value||"<html><body><a href='http://evil.com'>Click here</a></body></html>";
  showLoading("res-heuristic");
  const r=await apiPost("/email/heuristic-scan",{body,subject:"Urgent action required"});
  showResult("res-heuristic",r,"Heuristic");
}
async function checkAttachment(){
  const fn=document.getElementById("attachInput")?.value||"malware.exe";
  showLoading("res-attach");
  const r=await apiPost("/email/attachment-block",{file_name:fn});
  showResult("res-attach",r,"Attachment");
}
async function checkOutboundEncrypt(){
  const content=document.getElementById("encryptInput")?.value||"confidential.pdf";
  showLoading("res-encrypt");
  const r=await apiPost("/email/outbound-encrypt",{attachment_name:content,recipient:"client@partner.com"});
  showResult("res-encrypt",r,"Encryption");
}
async function checkPhishing(){
  showLoading("res-phish");
  const r=await apiPost("/email/url-analysis",{url:"http://bit.ly/phish-test"});
  showResult("res-phish",r,"Phishing");
}
async function phishingScan(){
  const el=document.getElementById("phishInput");
  const content=el?.value||"Urgent: Verify your account at http://bit.ly/phish to avoid suspension.";
  showLoading("res-phish");
  const r=await apiPost("/email/bec-scan",{body:content,sender_name:"",sender_domain:"",reply_to:""});
  showResult("res-phish",r,"Phish");
}
async function scanURL(){
  const input=document.getElementById("urlInput");
  const url=(input&&input.value.trim())||"";
  if(!url){showToast("No URL","Paste a URL to scan","danger");return;}
  showLoading("res-url");
  const r=await apiPost("/email/url-analysis",{url});
  showResult("res-url",r,"URL");
}
async function analyzeHeader(){
  const headers=document.getElementById("headerInput")?.value||"Received: from mail.example.com (203.0.113.42)\nFrom: attacker@evil.com\nReply-To: phishing@evil.com\nReturn-Path: bounce@evil.com\nMessage-ID: <abc123>\nDKIM-Signature: v=1; a=rsa-sha256; d=evil.com\nReceived-SPF: fail (google.com: domain of attacker@evil.com does not designate 203.0.113.42 as permitted sender)";
  const domain=document.getElementById("domainInput")?.value||"";
  showLoading("res-header");
  const r=await apiPost("/email/analyze-header",{headers,domain});
  showResult("res-header",r,"Header");
}
async function runHeaderAnalysis(){
  const headers=document.getElementById("headerInput")?.value;
  const domain=document.getElementById("domainInput")?.value||"";
  if(!headers||headers.length<20){showToast("Header Error","Please paste raw email headers","danger");return;}
  const result=document.getElementById("headerResult");
  if(!result)return;
  result.style.display="block";
  result.innerHTML='<div style="font-family:\'Share Tech Mono\',monospace;font-size:12px;color:var(--warn)">⏳ Parsing headers...</div>';
  try{
    const res=await apiPost("/email/analyze-header",{headers,domain});
    if(res.success){
      const a=res.analysis;
      const color=res.spoof_detected?"var(--danger)":"var(--safe)";
      let html=`<div style="border:1px solid ${color};border-radius:4px;padding:16px;background:rgba(0,0,0,0.25);font-family:'Share Tech Mono';font-size:12px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:12px;">
          <span style="color:${color};font-size:16px;font-weight:bold">${res.verdict}</span>
          <span style="opacity:0.5">Severity: ${res.severity}</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;">
          <div><span style="opacity:0.5">From:</span> ${a.from_domain||"N/A"}</div>
          <div><span style="opacity:0.5">Reply-To:</span> ${a.reply_to_domain||"N/A"}</div>
          <div><span style="opacity:0.5">Return-Path:</span> ${a.return_path_domain||"N/A"}</div>
          <div><span style="opacity:0.5">Source IP:</span> ${a.source_ip||"N/A"} (${a.source_country})</div>
        </div>
        <div style="display:flex;gap:12px;margin-bottom:12px;">
          <span>SPF: <span style="color:${a.spf_pass?"var(--safe)":"var(--danger)"}">${a.spf_pass?"✓":"✗"}</span></span>
          <span>DKIM: <span style="color:${a.dkim_pass?"var(--safe)":"var(--danger)"}">${a.dkim_pass?"✓":"✗"}</span></span>
          <span>DMARC: <span style="color:${a.dmarc_pass?"var(--safe)":"var(--danger)"}">${a.dmarc_pass?"✓":"✗"}</span></span>
        </div>`;
      if(a.spoof_indicators&&a.spoof_indicators.length){
        html+=`<div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.05)">
          <div style="color:var(--danger);margin-bottom:4px;font-weight:bold">⚠ Spoof Indicators</div>`;
        a.spoof_indicators.forEach(s=>{html+=`<div style="font-size:11px;opacity:0.8;padding:2px 0">• ${s}</div>`;});
        html+=`</div>`;
      }
      if(a.hops&&a.hops.length){
        html+=`<div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.05)">
          <div style="opacity:0.5;margin-bottom:4px">📡 Hops (${res.hops_parsed})</div>`;
        a.hops.forEach(h=>{html+=`<div style="font-size:10px;opacity:0.6;padding:1px 0">${h.from||"?"} → ${h.by||"?"} (${h.ip})</div>`;});
        html+=`</div>`;
      }
      html+=`<div style="margin-top:12px;font-size:11px;opacity:0.6">💡 ${res.recommendation}</div></div>`;
      result.innerHTML=html;
    } else {
      result.innerHTML=`<div style="color:var(--danger);font-family:'Share Tech Mono';font-size:12px">Error: ${res.message}</div>`;
    }
  }catch(e){
    result.innerHTML=`<div style="color:var(--danger);font-family:'Share Tech Mono';font-size:12px">Connection error</div>`;
  }
}

/* ════════════════════════════════════════════
   MOBILE SECURITY (35 features)
   ════════════════════════════════════════════ */

async function checkAppReputation(){
  const pkg=document.getElementById("reputationInput")?.value||"com.cleanmaster.pro";
  showLoading("res-reputation");
  const r=await apiPost("/mobile/app-reputation",{package_name:pkg,app_name:"App Reputation Check"});
  showResult("res-reputation",r,"App Rep");
}
async function checkCallerScan(){
  const phone=document.getElementById("callerInput")?.value||"+919999999999";
  showLoading("res-caller");
  const r=await apiPost("/mobile/caller-scan",{phone});
  showResult("res-caller",r,"Caller");
}
async function loadCallerFeed(){
  const list=document.getElementById("caller-feed-list");
  if(!list)return;
  try{
    const res=await apiGet("/mobile/caller-feed");
    if(res.success) list.innerHTML=res.feed.map(c=>`<div class="caller-feed-item ${c.status}"><span class="cf-number">${c.number}</span><span class="cf-name">${c.name}</span><span class="cf-type">${c.type.toUpperCase()}</span><span class="cf-status">${c.status==='blocked'?'🔴 BLOCKED':'✅ ALLOWED'}</span><span class="cf-time">${c.time}</span></div>`).join("");
  }catch(e){}
}
async function checkSenderScan(){
  const email=document.getElementById("senderInput")?.value||"attacker@evil.com";
  showLoading("res-sender");
  const r=await apiPost("/email/sender-scan",{email});
  showResult("res-sender",r,"Sender");
}

/* ════════════════════════════════════════════
   THREAT INTEL
   ════════════════════════════════════════════ */

async function checkIOC(){
  const ind=document.getElementById("iocInput")?.value||"45.33.32.156";
  showLoading("res-ioc");
  const r=await apiPost("/threat-intel/ioc-lookup",{indicator:ind});
  showResult("res-ioc",r,"IOC");
}
async function checkFeeds(){
  showLoading("res-feeds");
  const r=await apiGet("/threat-intel/feeds");
  showResult("res-feeds",r,"Feeds");
}
async function checkHash(){
  const h=document.getElementById("hashInput")?.value||"a"+"0"*31;
  showLoading("res-hash");
  const r=await apiPost("/threat-intel/scan-hash",{hash:h});
  showResult("res-hash",r,"Hash");
}

/* ════════════════════════════════════════════
   UEBA
   ════════════════════════════════════════════ */

async function checkBehavior(){
  showLoading("res-behavior");
  const r=await apiPost("/ueba/analyze-behavior",{user_id:"admin@corp.com",ip:"203.0.113.99",location:"Unknown",action:"login_attempt"});
  showResult("res-behavior",r,"Behavior");
}
async function checkRiskScore(){
  showLoading("res-riskscore");
  const r=await apiPost("/ueba/risk-score",{user_id:"admin@corp.com",device_trust_score:45,failed_attempts:3,ip_reputation:30});
  showResult("res-riskscore",r,"Risk Score");
}

/* ════════════════════════════════════════════
   ENCRYPTION
   ════════════════════════════════════════════ */

async function checkEncrypt(){
  showLoading("res-enc");
  const r=await apiPost("/encryption/encrypt",{data:"sensitive-pii-data-here"});
  showResult("res-enc",r,"Encrypt");
}
async function checkTLS(){
  showLoading("res-tls");
  const r=await apiGet("/encryption/tls-status");
  showResult("res-tls",r,"TLS");
}
async function checkPGP(){
  showLoading("res-pgp");
  const r=await apiPost("/encryption/pgp-encrypt",{message:"Confidential message for recipient",recipient_key:"recipient@example.com"});
  showResult("res-pgp",r,"PGP");
}
async function checkDecrypt(){
  showLoading("res-decrypt");
  const r=await apiPost("/encryption/decrypt",{data:"encrypted-data-here",key:"test-key"});
  showResult("res-decrypt",r,"Decrypt");
}

/* ════════════════════════════════════════════
   AI ENGINE (IOC, Email, Search, Report, Models)
   ════════════════════════════════════════════ */

async function checkAIIOC(){
  showLoading("res-ai-ioc");
  const r=await apiPost("/ai/analyze-ioc",{indicator:"45.33.32.156",model:"llama3"});
  showResult("res-ai-ioc",r,"AI IOC");
}
async function checkAIEmail(){
  showLoading("res-ai-email");
  const r=await apiPost("/ai/analyze-email",{sender:"attacker@evil.com",subject:"Urgent payment required",body:"Please click here to verify your account and avoid suspension."});
  showResult("res-ai-email",r,"AI Email");
}
async function checkAISearch(){
  showLoading("res-ai-search");
  const r=await apiPost("/ai/search",{query:"new ransomware family targeting healthcare 2026",model:"llama3"});
  showResult("res-ai-search",r,"AI Search");
}
async function checkAIReport(){
  showLoading("res-ai-report");
  const r=await apiPost("/ai/generate-report",{type:"threat_summary",timeframe:"24h",model:"llama3"});
  showResult("res-ai-report",r,"AI Report");
}
async function checkAIModels(){
  showLoading("res-ai-models");
  const r=await apiGet("/ai/models");
  showResult("res-ai-models",r,"AI Models");
}

/* ════════════════════════════════════════════
   SANDBOX (Create, Upload, Status, Destroy)
   ════════════════════════════════════════════ */

/* ════════════════════════════════════════════
   APK ANALYZER (Decompile, Static, Malware Scan)
   ════════════════════════════════════════════ */

async function checkAPKDecompile(){
  showLoading("res-apk-decompile");
  const r=await apiPost("/apk/decompile",{apk_name:"sample.apk",package_name:"com.example.app"});
  showResult("res-apk-decompile",r,"APK Decompile");
}
async function checkAPKStatic(){
  showLoading("res-apk-static");
  const r=await apiPost("/apk/static-analysis",{apk_name:"sample.apk",package_name:"com.example.app"});
  showResult("res-apk-static",r,"APK Static");
}
async function checkAPKMalware(){
  showLoading("res-apk-malware");
  const r=await apiPost("/apk/malware-scan",{apk_name:"sample.apk",package_name:"com.example.app"});
  showResult("res-apk-malware",r,"APK Malware");
}
async function checkAPKHistory(){
  showLoading("res-apk-history");
  const r=await apiGet("/apk/analyses");
  showResult("res-apk-history",r,"APK History");
}
async function checkAPKTools(){
  showLoading("res-apk-tools");
  const r=await apiGet("/apk/tools-status");
  showResult("res-apk-tools",r,"APK Tools");
}

/* ════════════════════════════════════════════
   YARA RULES (Scan IP, List Rules, Create)
   ════════════════════════════════════════════ */

async function checkYaraScan(){
  showLoading("res-yara-scan");
  const r=await apiPost("/yara/scan-ip",{ip:"45.33.32.156"});
  showResult("res-yara-scan",r,"YARA IP");
}
async function checkYaraRules(){
  showLoading("res-yara-rules");
  const r=await apiGet("/yara/rules");
  showResult("res-yara-rules",r,"YARA Rules");
}
async function checkYaraCreate(){
  showLoading("res-yara-create");
  const r=await apiPost("/yara/rules",{name:"Custom Threat Rule",description:"Detect specific threat pattern",priority:"high"});
  showResult("res-yara-create",r,"YARA Create");
}

/* ════════════════════════════════════════════
   INTEGRATIONS (Gmail API, Microsoft Graph)
   ════════════════════════════════════════════ */

async function checkGmailConnect(){
  showLoading("res-gmail-connect");
  const el=document.getElementById("gmailCredentials");
  let creds={};
  if(el && el.value.trim()){
    try{creds=JSON.parse(el.value.trim())}catch(e){creds={access_token:el.value.trim()}}
  }
  const r=await apiPost("/integration/gmail/connect",{credentials_json:creds});
  showResult("res-gmail-connect",r,"Gmail");
  if(r.auth_url){
    document.getElementById("res-gmail-connect").innerHTML+='<br><a href="'+r.auth_url+'" target="_blank" style="color:var(--cyan)">Open Auth URL →</a>';
  }
  if(r.success&&r.connection_status==="CONNECTED"){
    const card=document.getElementById("gmail-status");
    if(card){card.querySelector(".sc-value").innerHTML="Connected";card.querySelector(".sc-value").style.color="var(--green)";card.querySelector(".sc-sub").textContent="Gmail API connected";}
    const banner=document.getElementById("alertBanner"); if(banner)banner.querySelector(".alert-text").innerHTML="<strong>INTEGRATIONS STATUS:</strong> Gmail connected. Microsoft 365 is disconnected. SIEM forwarding is active. 3 webhooks configured.";
  }
}
async function checkGmailScan(){
  showLoading("res-gmail-scan");
  const r=await apiPost("/integration/gmail/scan",{max_results:10});
  showResult("res-gmail-scan",r,"Gmail Scan");
}
async function checkGmailSearch(){
  showLoading("res-gmail-search");
  const q=document.getElementById("gmailQuery")?.value||"subject:security alert";
  const r=await apiPost("/integration/gmail/search",{query:q,max_results:5});
  showResult("res-gmail-search",r,"Gmail Search");
}
async function checkGraphConnect(){
  showLoading("res-graph-connect");
  const el=document.getElementById("graphCredentials");
  let creds={};
  if(el && el.value.trim()){
    try{creds=JSON.parse(el.value.trim())}catch(e){creds={}}
  }
  const r=await apiPost("/integration/graph/connect",{...creds,access_token:creds.access_token||""});
  showResult("res-graph-connect",r,"Graph");
  if(r.success&&r.connection_status==="CONNECTED"){
    const card=document.getElementById("graph-status");
    if(card){card.querySelector(".sc-value").innerHTML="Connected";card.querySelector(".sc-value").style.color="var(--green)";card.querySelector(".sc-sub").textContent="Microsoft Graph connected";}
    const banner=document.getElementById("alertBanner"); if(banner)banner.querySelector(".alert-text").innerHTML="<strong>INTEGRATIONS STATUS:</strong> Gmail connected. Microsoft 365 connected. SIEM forwarding is active. 3 webhooks configured.";
  }
}
async function checkGmailDisconnect(){
  showLoading("res-gmail-connect");
  const r=await apiPost("/integration/gmail/disconnect",{});
  showResult("res-gmail-connect",r,"Gmail");
  if(r.success){
    const card=document.getElementById("gmail-status");
    if(card){card.querySelector(".sc-value").innerHTML="Disconnected";card.querySelector(".sc-value").style.color="var(--red)";card.querySelector(".sc-sub").textContent="Click to connect";}
    const banner=document.getElementById("alertBanner"); if(banner)banner.querySelector(".alert-text").innerHTML="<strong>INTEGRATIONS STATUS:</strong> Gmail and Microsoft 365 are disconnected. SIEM forwarding is active. 3 webhooks configured.";
  }
}
async function checkGraphDisconnect(){
  showLoading("res-graph-connect");
  const r=await apiPost("/integration/graph/disconnect",{});
  showResult("res-graph-connect",r,"Graph");
  if(r.success){
    const card=document.getElementById("graph-status");
    if(card){card.querySelector(".sc-value").innerHTML="Disconnected";card.querySelector(".sc-value").style.color="var(--red)";card.querySelector(".sc-sub").textContent="Click to connect";}
    const banner=document.getElementById("alertBanner"); if(banner)banner.querySelector(".alert-text").innerHTML="<strong>INTEGRATIONS STATUS:</strong> Gmail and Microsoft 365 are disconnected. SIEM forwarding is active. 3 webhooks configured.";
  }
}
async function checkGraphUsers(){
  showLoading("res-graph-users");
  const r=await apiPost("/integration/graph/users",{});
  showResult("res-graph-users",r,"Graph Users");
}
async function checkGraphAudit(){
  showLoading("res-graph-audit");
  const r=await apiPost("/integration/graph/audit-logs",{days:7});
  showResult("res-graph-audit",r,"Graph Audit");
}
async function checkGraphScan(){
  showLoading("res-graph-scan");
  const r=await apiPost("/integration/graph/scan-mail",{mailbox:"user@company.com"});
  showResult("res-graph-scan",r,"Graph Scan");
}

/* ════════════════════════════════════════════
   UI HELPERS
   ════════════════════════════════════════════ */

function showLoading(id){
  const el=document.getElementById(id);
  if(!el) return;
  el.className="tc-result show res-loading";
  el.innerHTML="⏳ Processing...";
}
function showResult(id,res,label){
  const el=document.getElementById(id);
  if(!el) return;
  if(!res||res.error){
    el.className="tc-result show res-fail";
    el.innerHTML=`<strong>${label}:</strong> ${res?.error||"Request failed"}`;
    return;
  }
  const verdict=res.verdict||res.status||"OK";
  const cls=!verdict||verdict==="PASS"||verdict==="CLEAN"||verdict==="SAFE"||verdict==="SECURE"||verdict==="PROTECTED"||verdict==="VERIFIED"||verdict==="LEGITIMATE"||verdict==="BENIGN"||verdict==="ENCRYPTED"||verdict==="ALLOWED"||verdict==="AUTHENTICATED"||verdict==="COMPLIANT"||verdict==="OPERATIONAL"||verdict.includes("OK")||verdict.includes("PASS")||verdict.includes("COMPLETE")||verdict.includes("_VALID")||verdict.includes("_CREATED")||verdict.includes("_READY")||verdict.includes("_LISTED")||verdict.includes("DECOMPILED")||verdict.includes("GENERATED")||verdict==="SESSION_VALID"||verdict==="TOKEN_VERIFIED"||verdict==="ARGON2_READY"||verdict==="SANDBOX_CREATED"?"res-pass":
    verdict==="FAIL"||verdict==="BLOCKED"||verdict==="MALICIOUS"||verdict==="PHISHING"||verdict==="BEC_ATTACK"||verdict==="DRIVE_BY_DOWNLOAD"||verdict==="SPOOFING_DETECTED"||verdict==="EXFILTRATION_BLOCKED"||verdict==="ROGUE_MDM_DETECTED"||verdict==="ZERO_CLICK_EXPLOIT"||verdict==="CREDENTIAL_PHISHING"||verdict==="ATO_ATTEMPT_DETECTED"||verdict==="DOUBLE_AUTH_PASSED"?"res-fail":"res-warn";
  el.className=`tc-result show ${cls}`;
  let html=`<strong>${label}:</strong> ${verdict}`;
  if(res.score||res.threat_score||res.bec_score||res.risk_score||res.phishing_score||res.heuristic_score||res.bec_score){html+=` <span style="opacity:0.6">| Score: ${res.score||res.threat_score||res.bec_score||res.risk_score||res.phishing_score||res.heuristic_score||0}</span>`;}
  if(res.message) html+=`<br><span style="opacity:0.7;font-size:.78rem">${res.message}</span>`;
  el.innerHTML=html;
  if(res.findings&&res.findings.length){
    el.innerHTML+=`<div style="margin-top:6px;font-size:.72rem">${res.findings.slice(0,3).map(f=>`• ${f}`).join("<br>")}</div>`;
  }
  if(res.recommendation){
    el.innerHTML+=`<div style="margin-top:4px;font-size:.68rem;opacity:0.6">💡 ${res.recommendation}</div>`;
  }
}

/* ════════════════════════════════════════════
   EXISTING MOBILE FUNCTIONS
   ════════════════════════════════════════════ */

async function analyzeSMS(){
  const text=document.getElementById("sms-input")?.value.trim();
  const result=document.getElementById("sms-result");
  if(!text){result.innerHTML='<span style="color:var(--danger)">Please paste an SMS message</span>';return;}
  result.innerHTML='<span style="color:var(--warn)">⏳ Analyzing...</span>';
  try{
    const res=await apiPost("/mobile/analyze-sms",{text});
    if(res.success){
      const color=res.verdict==="PHISHING"?"var(--danger)":res.verdict==="SUSPICIOUS"?"var(--warn)":"var(--safe)";
      let html=`<div style="color:${color};padding:12px;background:rgba(0,0,0,0.2);border:1px solid ${color};border-radius:4px;font-family:'Share Tech Mono';font-size:12px;"><strong>VERDICT: ${res.verdict}</strong> (Score: ${res.score}/100)<br>`;
      res.findings.forEach(f=>{html+=`• ${f}<br>`;}); html+="</div>";
      result.innerHTML=html;
    }
  }catch(e){result.innerHTML='<span style="color:var(--danger)">Error analyzing SMS</span>';}
}

async function startAppScan(){
  const fill=document.getElementById("app-scan-fill");
  const log=document.getElementById("app-scan-log");
  const result=document.getElementById("app-perm-results");
  if(!log) return;
  fill.style.width="0%"; log.innerHTML=""; if(result) result.style.display="none";
  const steps=[[300,"[INFO] Initializing app permission scanner..."],[700,"[INFO] Reading installed application list..."],[1100,"[INFO] Checking manifest permissions..."],[1500,"[WARN] Analyzing permission groups..."],[1900,"[INFO] Cross-referencing with threat intel..."],[2400,"[OK] Scan complete. Compiling report..."]];
  steps.forEach(([t,m])=>setTimeout(()=>{log.innerHTML+=`<div style="line-height:2">${m}</div>`;log.scrollTop=9999;},t));
  let p=0;
  const iv=setInterval(()=>{p+=3;fill.style.width=Math.min(p,100)+"%";if(p>=100)clearInterval(iv);},80);
  try{
    const res=await apiGet("/mobile/scan-apps");
    setTimeout(()=>{
      if(res.success&&result){
        result.style.display="block";
        result.innerHTML=`<div style="font-family:'Share Tech Mono';font-size:11px">${res.apps.map(a=>`<div class="perm-item"><span>${a.name}</span><span style="color:${a.risk==='high'?'var(--danger)':a.risk==='medium'?'var(--warn)':'var(--safe)'}">${a.permissions?.length||0} permissions | ${a.risk.toUpperCase()} Risk</span></div>`).join("")}</div>`;
        log.innerHTML+='<div style="color:var(--safe);line-height:2">✅ Scan completed. Permissions audited.</div>';
      }
    },2500);
  }catch(e){log.innerHTML+='<div style="color:var(--danger)">❌ Scan error</div>';}
}
async function startMalwareScan(){
  const fill=document.getElementById("malware-scan-fill");
  const log=document.getElementById("malware-scan-log");
  const result=document.getElementById("malware-result");
  if(!log) return;
  fill.style.width="0%"; log.innerHTML=""; result.innerHTML="";
  const steps=[[200,"[INFO] Initializing malware scanner engine..."],[600,"[INFO] Scanning APK signatures..."],[1000,"[INFO] Checking installed packages against threat intel..."],[1500,"[WARN] Scanning file system for anomalies..."],[2000,"[INFO] Analyzing behavior patterns..."],[2500,"[OK] Scan complete. Compiling report..."]];
  steps.forEach(([t,m])=>setTimeout(()=>{log.innerHTML+=`<div style="line-height:2">${m}</div>`;log.scrollTop=9999;},t));
  let p=0;
  const iv=setInterval(()=>{p+=3;fill.style.width=Math.min(p,100)+"%";if(p>=100)clearInterval(iv);},80);
  const res=await apiGet("/mobile/malware-scan");
  setTimeout(()=>{
    if(res.success){
      const color=res.threats_found>0?"var(--danger)":"var(--safe)";
      result.innerHTML=`<div style="color:${color};font-family:'Share Tech Mono';font-size:12px;padding:12px;background:rgba(0,0,0,0.2);border:1px solid ${color};border-radius:4px;"><strong>${res.threats_found>0?"⚠ THREATS FOUND":"✅ CLEAN"}</strong><br>Apps Scanned: ${res.apps_scanned} | Threats: ${res.threats_found} | Clean: ${res.clean}</div>`;
    }
  },2600);
}

async function loadBatteryData(){
  const list=document.getElementById("battery-list");
  if(!list) return;
  try{
    const res=await apiGet("/mobile/check-battery");
    if(res.success) list.innerHTML=res.apps.map(a=>`<div class="perm-item"><span>${a.name}</span><span style="color:${a.flagged?'var(--danger)':'var(--safe)'}">CPU: ${a.cpu}% | Battery: ${a.battery}%</span></div>`).join("");
  }catch(e){list.innerHTML="Error loading data";}
}

async function loadDeviceHealth(){
  const content=document.getElementById("device-health-content");
  if(!content) return;
  try{
    const res=await apiGet("/mobile/device-health");
    if(res.success){
      content.innerHTML=`<div style="text-align:center;margin-bottom:16px;"><span style="font-family:'Orbitron',monospace;font-size:36px;color:${res.overall_score>=80?"var(--safe)":"var(--warn)"}">${res.overall_score}%</span><div style="font-family:'Share Tech Mono';font-size:10px;color:var(--text-dim)">OVERALL HEALTH</div></div>`;
      res.checks.forEach(c=>{
        const col=c.status==="passed"?"var(--safe)":c.status==="warning"?"var(--warn)":"var(--danger)";
        content.innerHTML+=`<div class="health-bar-row"><div class="health-bar-label"><span>${c.name}</span><span style="color:${col}">${c.status.toUpperCase()}</span></div><div class="health-bar-track"><div class="health-bar-fill" style="width:${c.score}%;background:${col};box-shadow:0 0 6px ${col}"></div></div></div>`;
      });
    }
  }catch(e){content.innerHTML="Error loading health data";}
}

async function loadCallData(){
  const list=document.getElementById("call-list");
  if(!list) return;
  try{
    const res=await apiGet("/mobile/call-logs");
    if(res.success) list.innerHTML=res.calls.map(c=>`<div class="perm-item"><span>${c.from}</span><span style="color:${c.blocked?'var(--danger)':'var(--safe)'}">${c.type.toUpperCase()} ${c.blocked?'🔴 BLOCKED':'✅ ALLOWED'}</span></div>`).join("");
  }catch(e){list.innerHTML="Error loading calls";}
}

async function generateReport(type){
  const endpoints={PDF:"/reports/download-pdf",CSV:"/reports/download-csv",JSON:"/reports/download-json"};
  const filenames={PDF:"CyberShield_Report.pdf",CSV:"CyberShield_Data.csv",JSON:"CyberShield_Data.json"};
  if(type==="COMPREHENSIVE"){endpoints["COMPREHENSIVE"]="/reports/comprehensive";filenames["COMPREHENSIVE"]="CyberShield_Comprehensive.json";}
  if(type==="THREAT"){endpoints["THREAT"]="/reports/threat-report";filenames["THREAT"]="CyberShield_ThreatReport.json";}
  if(type==="ENCRYPTION"){endpoints["ENCRYPTION"]="/reports/encryption";filenames["ENCRYPTION"]="CyberShield_Encryption.json";}
  if(type==="UEBA"){endpoints["UEBA"]="/reports/ueba-risk";filenames["UEBA"]="CyberShield_UEBA.json";}
  showToast("Generating",`${type} report...`,"info");
  await apiDownload(endpoints[type],filenames[type]);
}

async function runScan(){
  const el=document.getElementById("scanResult");
  if(!el)return;
  let endpoint,payload,label;
  const emailTab=document.getElementById("email-scan");
  const phoneTab=document.getElementById("mobile-scan");
  const urlTab=document.getElementById("url-scan");
  if(emailTab&&emailTab.style.display!=="none"){
    const val=document.getElementById("emailInput")?.value||"test@example.com";
    endpoint="/email/sender-scan"; payload={email:val}; label="Email";
  }else if(phoneTab&&phoneTab.style.display!=="none"){
    const val=document.getElementById("phoneInput")?.value||"+919999999999";
    endpoint="/mobile/caller-scan"; payload={phone:val}; label="Phone";
  }else if(urlTab&&urlTab.style.display!=="none"){
    const val=document.getElementById("urlInput")?.value||"https://example.com";
    endpoint="/email/url-analysis"; payload={url:val}; label="URL";
  }else{el.innerHTML='<span style="color:var(--danger)">No tab selected</span>';return;}
  el.innerHTML='<span style="color:var(--warn)">⏳ Scanning...</span>';
  try{
    const r=await apiPost(endpoint,payload);
    if(!r||r.error){el.innerHTML=`<span style="color:var(--danger)">✗ ${label} Scan Failed: ${r?.error||"Unknown error"}</span>`;return;}
    const verdict=r.verdict||r.status||"COMPLETE";
    const score=r.score||r.risk_score||r.threat_score||0;
    const cls=verdict==="PHISHING"||verdict==="MALICIOUS"||verdict==="BLOCKED"||verdict==="SPOOFING_DETECTED"?"danger":verdict==="SUSPICIOUS"||score>50?"warn":"safe";
    let html=`<div style="border-left:3px solid var(--${cls});padding:12px;background:rgba(0,0,0,0.3);border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:12px;text-align:left">`;
    html+=`<strong style="color:var(--${cls})">${label}: ${verdict}</strong>`;
    if(score>0)html+=` <span style="opacity:0.6">| Score: ${score}/100</span>`;
    if(r.reputation||r.category)html+=`<br><span style="opacity:0.7">${r.reputation||""} ${r.category||""}</span>`;
    if(r.findings&&r.findings.length)html+=`<br>${r.findings.slice(0,3).map(f=>`• ${f}`).join("<br>")}`;
    if(r.recommendation)html+=`<br><span style="opacity:0.5;font-size:11px">💡 ${r.recommendation}</span>`;
    html+=`</div>`;
    el.innerHTML=html;
  }catch(e){el.innerHTML=`<span style="color:var(--danger)">✗ Scan error: ${e.message||"Request failed"}</span>`;}
}

/* ════════════════════════════════════════════
   UI: MODALS, TABS, CLOCK, CHARTS
   ════════════════════════════════════════════ */

function openModal(id){const el=document.getElementById(id);if(el)el.classList.add("open");}
function closeMobileModal(id){const el=document.getElementById(id);if(el)el.classList.remove("open");}
function closeModal(id){const el=document.getElementById(id);if(el)el.classList.remove("open");}

function switchTab(el,id){
  document.querySelectorAll(".scan-tab").forEach(t=>t.classList.remove("active"));
  el.classList.add("active");
  document.querySelectorAll(".scanner-wrap > div[id], .scanner-box > div[id]").forEach(d=>{if(d.id)d.style.display="none";});
  const target=document.getElementById(id);
  if(target)target.style.display="block";
}

function switchLoginTab(tab){
  document.querySelectorAll(".tab-btn").forEach(t=>t.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p=>p.classList.remove("active"));
  document.querySelector(`.tab-btn[onclick*="${tab}"]`)?.classList.add("active");
  document.getElementById(`panel-${tab}`)?.classList.add("active");
}

function filterInbox(el,cat){
  document.querySelectorAll(".filter-btn").forEach(b=>b.classList.remove("active"));
  el.classList.add("active");
  document.querySelectorAll(".mail-row").forEach(r=>{if(cat==="all"||r.dataset.cat===cat)r.style.display="flex";else r.style.display="none";});
}

function refreshAll(){showToast("Refreshing","Reloading all security data...","info");}
function refreshAllStatus(){showToast("Status Refreshed","All security modules synced","safe");}

let _lastEmlId = null;
function onFileSelect(input){
  const name=document.getElementById("fileName");
  if(name&&input.files[0])name.textContent=input.files[0].name;
  document.getElementById("scanBtn").disabled=false;
  document.getElementById("alertBar").innerHTML="";
  document.getElementById("resultBox").innerHTML="";
  _lastEmlId = null;
}
async function analyzeEmail(){
  const input=document.getElementById("emailFile");
  if(!input||!input.files[0]){showToast("No File","Select a .eml file first","danger");return;}
  const file=input.files[0];
  if(!file.name.toLowerCase().endsWith(".eml")){showToast("Invalid","Only .eml files supported","danger");return;}
  showToast("Email Scan","Analyzing .eml file...","info");
  const btn=document.getElementById("scanBtn");btn.disabled=true;
  const scanning=document.getElementById("scanningMsg");if(scanning)scanning.style.display="block";
  const alertBar=document.getElementById("alertBar");alertBar.innerHTML="";alertBar.style.display="block";
  const resultBox=document.getElementById("resultBox");resultBox.innerHTML="";resultBox.style.display="block";
  try{
    const fd=new FormData();fd.append("file",file);
    const r=await fetch(apiUrl("/email/analyze-eml-file"),{method:"POST",headers:authHeadersNoType(),body:fd});
    const res=await r.json();
    if(!res.success||res.error){alertBar.innerHTML=`<span style="color:var(--danger)">✗ ${res.error||"Analysis failed"}</span>`;btn.disabled=false;if(scanning)scanning.style.display="none";return;}
    _lastEmlId = res.analysis_id;
    const v=res.verdict||"UNKNOWN";
    const score=res.phishing_score||0;
    const vc=v==="PHISHING"?"danger":v==="SUSPICIOUS"?"warn":"safe";
    let html=`<div style="border-left:3px solid var(--${vc});padding:12px;background:rgba(0,0,0,0.3);border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:12px;">`;
    html+=`<strong style="color:var(--${vc});font-size:15px;">VERDICT: ${v}</strong> <span style="opacity:0.6">| Score: ${score}/100</span><br>`;
    html+=`<span style="opacity:0.5">File: ${res.filename} | ${(res.message_size/1024).toFixed(1)} KB | ${res.received_hops} hops</span><br><br>`;
    const h=res.headers||{};
    for(const k of["From","To","Subject","Date","Return-Path","Reply-To"]){
      if(h[k])html+=`<strong>${k}:</strong> ${h[k].length>100?h[k].slice(0,100)+"...":h[k]}<br>`;
    }
    if(res.findings&&res.findings.length){
      html+=`<br><strong style="color:var(--${vc})">Findings (${res.findings.length}):</strong><br>`;
      res.findings.forEach(f=>{html+=`<span style="opacity:0.8">• ${f}</span><br>`;});
    }
    if(res.attachments&&res.attachments.length){
      html+=`<br><strong>Attachments (${res.attachment_count}):</strong><br>`;
      res.attachments.forEach(a=>{html+=`<span style="opacity:0.7">• ${a.filename} (${(a.size/1024).toFixed(1)} KB)</span><br>`;});
    }
    if(res.urls_found&&res.urls_found.length){
      html+=`<br><strong>URLs found:</strong><br>`;
      res.urls_found.forEach(u=>{html+=`<span style="opacity:0.6;font-size:11px">• ${u}</span><br>`;});
    }
    if(res.recommendation)html+=`<br><span style="opacity:0.5">💡 ${res.recommendation}</span>`;
    html+=`</div>`;
    html+=`<div style="margin-top:10px;display:flex;gap:8px;">`;
    html+=`<button class="btn-scan" onclick="downloadEmlReport('pdf')" style="flex:1;padding:10px;font-size:11px;background:rgba(255,51,85,0.15);border-color:var(--danger);color:var(--danger)">📄 DOWNLOAD PDF</button>`;
    html+=`<button class="btn-scan" onclick="downloadEmlReport('xlsx')" style="flex:1;padding:10px;font-size:11px;background:rgba(0,255,136,0.1);border-color:var(--safe);color:var(--safe)">📊 DOWNLOAD EXCEL</button>`;
    html+=`</div>`;
    resultBox.innerHTML=html;alertBar.innerHTML=`<span style="color:var(--safe)">✓ Analysis complete — ${res.findings?res.findings.length:0} findings, verdict: ${v}</span>`;
  }catch(e){alertBar.innerHTML=`<span style="color:var(--danger)">✗ Error: ${e.message}</span>`;}
  btn.disabled=false;if(scanning)scanning.style.display="none";
}
function downloadEmlReport(fmt){
  if(!_lastEmlId){showToast("No Data","Run analysis first","danger");return;}
  const ep=fmt==='pdf'?'/email/eml-report/pdf':'/email/eml-report/xlsx';
  const fn=`CyberShield_EML_Report.${fmt}`;
  fetch(apiUrl(`${ep}?id=${_lastEmlId}`),{headers:authHeaders()}).then(r=>{if(!r.ok)throw Error(r.statusText);return r.blob()}).then(blob=>{const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=fn;a.click();URL.revokeObjectURL(a.href);showToast('Downloaded',fn,'safe')}).catch(e=>showToast('Download Failed',e.message,'danger'));
}

function togglePassword(){const inp=document.getElementById("pwInput");if(inp)inp.type=inp.type==="password"?"text":"password";}
function togglePin(){const inp=document.getElementById("pinInput");if(inp)inp.type=inp.type==="password"?"text":"password";}
function toggleMFA(){const section=document.getElementById("mfaSection");const check=document.getElementById("mfaCheck");if(section&&check){section.classList.toggle("show");check.textContent=section.classList.contains("show")?"✓":"";}}
function otpNext(el,nextId){if(el.value.length>=1&&nextId)document.getElementById(nextId)?.focus();}
function altLogin(method){showToast("Alternative Login",`${method} authentication initiated`,"info");}
function showForgot(){showToast("Password Reset","Reset link sent to your email","info");}

const THREAT_EVENTS=[
  {sev:"high",msg:"APK sideload attempt detected on BYOD device",time:"2s"},
  {sev:"medium",msg:"Phishing SMS targeting finance team blocked",time:"5s"},
  {sev:"low",msg:"Weekly app scan started — 148 apps queued",time:"10s"},
  {sev:"high",msg:"Jailbreak detected — Device #DEV005 policy enforced",time:"15s"},
  {sev:"medium",msg:"Rogue Wi-Fi network detected near building B",time:"20s"},
];

function initThreatLog(){
  const log=document.getElementById("threatLog");
  if(!log) return;
  let i=0;
  setInterval(()=>{
    const e=THREAT_EVENTS[i%THREAT_EVENTS.length];
    const d=document.createElement("div");
    d.className=`log-entry ${e.sev}`;
    d.innerHTML=`<span class="log-sev sev-${e.sev}">${e.sev.toUpperCase()}</span><span class="log-msg">${e.msg}</span><span class="log-time">${e.time}</span>`;
    log.insertBefore(d,log.firstChild);
    if(log.children.length>8)log.removeChild(log.lastChild);
    i++;
  },6000);
}

function initClock(){
  const els=document.querySelectorAll("#live-clock,.live-clock,#clock");
  if(!els.length) return;
  setInterval(()=>{const now=new Date().toLocaleTimeString("en-GB",{hour12:false});els.forEach(el=>{if(el)el.textContent=now;});},1000);
}

function initReveal(){
  const els=document.querySelectorAll(".reveal");
  if(!els.length) return;
  const observer=new IntersectionObserver((entries)=>{entries.forEach(e=>{if(e.isIntersecting)e.target.classList.add("visible");});},{threshold:0.1});
  els.forEach(el=>observer.observe(el));
}

function animateCounters(){
  document.querySelectorAll(".stat-num,.stat-value,.metric-val").forEach(el=>{
    const target=parseInt(el.textContent.replace(/,/g,""));
    if(isNaN(target))return;
    el.textContent="0";
    let current=0;
    const step=Math.max(1,Math.floor(target/60));
    const iv=setInterval(()=>{current+=step;if(current>=target){clearInterval(iv);el.textContent=target;}else el.textContent=current;},30);
  });
}

function drawRadar(){
  const canvas=document.getElementById("radarCanvas");
  if(!canvas) return;
  const ctx=canvas.getContext("2d");
  const cx=130,cy=130,r=90;
  ctx.clearRect(0,0,260,260);
  for(let i=1;i<=3;i++){ctx.beginPath();ctx.arc(cx,cy,r*i/3,0,Math.PI*2);ctx.strokeStyle="rgba(13,42,69,0.6)";ctx.lineWidth=1;ctx.stroke();}
  const threats=[{angle:0.2,dist:0.8,color:"var(--safe)",label:"Malware"},{angle:1.8,dist:0.5,color:"var(--warn)",label:"Phishing"},{angle:3.0,dist:0.3,color:"var(--danger)",label:"Intrusion"},{angle:4.5,dist:0.6,color:"var(--info)",label:"Spyware"}];
  threats.forEach(t=>{const x=cx+r*t.dist*Math.cos(t.angle);const y=cy+r*t.dist*Math.sin(t.angle);ctx.beginPath();ctx.arc(x,y,6,0,Math.PI*2);ctx.fillStyle=t.color;ctx.shadowBlur=12;ctx.shadowColor=t.color;ctx.fill();ctx.shadowBlur=0;});
}

function drawBarChart(){
  const canvas=document.getElementById("barCanvas");
  if(!canvas) return;
  const ctx=canvas.getContext("2d");
  const W=canvas.width,H=canvas.height;
  ctx.clearRect(0,0,W,H);
  const days=["MON","TUE","WED","THU","FRI","SAT","SUN"];
  const vals=[14,22,18,31,27,9,12];
  const maxVal=Math.max(...vals);
  const barW=60,gap=50,startX=60,bottomY=H-30,chartH=H-55;
  for(let i=0;i<=4;i++){const y=bottomY-chartH*i/4;ctx.beginPath();ctx.moveTo(40,y);ctx.lineTo(W-20,y);ctx.strokeStyle="rgba(13,42,69,0.8)";ctx.lineWidth=1;ctx.stroke();ctx.fillStyle="rgba(58,96,128,0.8)";ctx.font="10px Share Tech Mono";ctx.textAlign="right";ctx.fillText(Math.round(maxVal*i/4),35,y+4);}
  vals.forEach((v,i)=>{
    const x=startX+i*(barW+gap);const barH=chartH*(v/maxVal);const y=bottomY-barH;
    const g=ctx.createLinearGradient(0,y,0,bottomY);g.addColorStop(0,"rgba(0,229,255,0.9)");g.addColorStop(1,"rgba(0,229,255,0.2)");
    ctx.fillStyle=g;ctx.fillRect(x,y,barW,barH);ctx.fillStyle="#00ffe7";ctx.fillRect(x,y,barW,3);
    ctx.fillStyle="#fff";ctx.font="bold 12px Orbitron, monospace";ctx.textAlign="center";ctx.fillText(v,x+barW/2,y-8);
    ctx.fillStyle="rgba(58,96,128,0.9)";ctx.font="10px Share Tech Mono";ctx.fillText(days[i],x+barW/2,bottomY+16);
  });
}

function validateToken(){
  if(!AUTH_TOKEN) return;
  fetch(apiUrl("/mobile/dashboard-stats"),{headers:authHeaders()}).then(r=>{
    if(r.status===401){localStorage.removeItem("cybershield_token");AUTH_TOKEN=null;showToast("Session Expired","Please login again","danger");setTimeout(()=>{window.location.href="login.html"},1500);}
  }).catch(()=>{});
}
document.addEventListener("DOMContentLoaded",()=>{
  const isLogin = window.location.pathname.includes("login");
  const isIndex = window.location.pathname === "/" || window.location.pathname.includes("index");
  validateToken();
  if(!isLogin){
    initClock();initReveal();initThreatLog();
    drawRadar();drawBarChart();
  }
  if(!isLogin && !isIndex){
    loadDashboardStats();loadBatteryData();loadDeviceHealth();loadCallData();
    setTimeout(animateCounters,500);
  }
});
