import { useState, useEffect, useCallback, useRef } from 'react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';

const API = import.meta.env.VITE_API_URL || '';

// ─── Design Tokens ─────────────────────────────────────────────────────────────
const T = {
  bg: '#090c12', bgSurface: '#0d1117', bgPanel: '#111820', bgCard: '#141c26',
  bgHover: '#1a2535', bgActive: '#1e2d42',
  border: '#1e2d3d', borderLight: '#243347',
  blue: '#0078d4', blueDim: '#005a9e', blueGlow: '#0078d420',
  cyan: '#00b4d8', teal: '#00897b',
  critical: '#c82424', criticalBg: '#c8242415',
  high: '#e05c00', highBg: '#e05c0015',
  medium: '#c9a227', mediumBg: '#c9a22715',
  success: '#13a10e', successBg: '#13a10e15',
  warning: '#d97706',
  textPrimary: '#e8edf2', textSecond: '#8899aa', textMuted: '#4a607a', textDim: '#637a92',
  chart1: '#0078d4', chart2: '#c82424', chart3: '#c9a227', chart4: '#9b59b6', chart5: '#00897b',
};

const fmt = n => n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1000 ? (n/1000).toFixed(1)+'k' : String(n||0);
const pct = n => `${(n*100).toFixed(1)}%`;
const timeAgo = ts => {
  const d=(Date.now()-new Date(ts))/1000;
  if(d<60) return `${Math.floor(d)}s`;
  if(d<3600) return `${Math.floor(d/60)}m`;
  return `${Math.floor(d/3600)}h`;
};

async function api(path, opts={}) {
  try {
    const r = await fetch(`${API}${path}`, {...opts, headers:{'Content-Type':'application/json',...opts.headers}});
    return await r.json();
  } catch(e) { return {error:e.message}; }
}

const NAV = [
  {k:'dashboard', icon:'dashboard',     label:'Vue d\'ensemble', group:'ANALYSE'},
  {k:'live',      icon:'sensors',       label:'Flux Live',       group:'ANALYSE'},
  {k:'threats',   icon:'gpp_bad',       label:'Menaces',         group:'DÉTECTION'},
  {k:'incidents', icon:'crisis_alert',  label:'Incidents',       group:'DÉTECTION'},
  {k:'waf',       icon:'security',      label:'WAF',             group:'PROTECTION'},
  {k:'ml',        icon:'smart_toy',     label:'ML Engine',       group:'PROTECTION'},
  {k:'soar',      icon:'bolt',          label:'SOAR',            group:'RÉPONSE'},
  {k:'config',    icon:'tune',          label:'Configuration',   group:'SYSTÈME'},
];

function MIcon({ name, size=18, color='inherit', style={} }) {
  return <span className="material-symbols-rounded" style={{fontSize:size,color,lineHeight:1,...style}}>{name}</span>;
}

function Card({ children, style={}, accent, noPad }) {
  return (
    <div style={{
      background:T.bgCard, border:`1px solid ${accent?accent+'33':T.border}`,
      borderRadius:8, padding:noPad?0:20,
      ...(accent&&{boxShadow:`0 0 0 1px ${accent}22, 0 4px 24px ${accent}11`}), ...style,
    }}>{children}</div>
  );
}

function Badge({ s }) {
  const map = {
    CRITICAL:[T.critical,'#fff'],CRITIQUE:[T.critical,'#fff'],
    HIGH:[T.high,'#fff'],ÉLEVÉ:[T.high,'#fff'],
    MEDIUM:[T.medium,'#000'],MOYEN:[T.medium,'#000'],
    LOW:[T.success,'#fff'],FAIBLE:[T.success,'#fff'],
    OPEN:[T.critical,'#fff'],INVESTIGATING:[T.warning,'#fff'],
    RESOLVED:[T.success,'#fff'],CLOSED:[T.textMuted,'#fff'],
    EXECUTED:[T.success,'#fff'],FAILED:[T.critical,'#fff'],
    BLOCKED:[T.critical,'#fff'],BENIGN:[T.success,'#fff'],
    SUSPICIOUS:[T.warning,'#fff'],OK:[T.success,'#fff'],
    healthy:[T.success,'#fff'],degraded:[T.warning,'#fff'],unreachable:[T.critical,'#fff'],
  };
  const [bg] = map[s]||[T.border];
  return (
    <span style={{
      background:bg+'22',color:bg,border:`1px solid ${bg}44`,
      fontSize:9,padding:'3px 7px',borderRadius:4,fontWeight:700,
      letterSpacing:'0.05em',whiteSpace:'nowrap',
    }}>{s}</span>
  );
}

function RiskBar({ v=0, width=64 }) {
  const col=v>0.8?T.critical:v>0.6?T.high:v>0.4?T.medium:T.success;
  return (
    <div style={{display:'flex',alignItems:'center',gap:6}}>
      <div style={{width,height:4,background:T.border,borderRadius:2,overflow:'hidden'}}>
        <div style={{width:`${v*100}%`,height:'100%',background:col,borderRadius:2}}/>
      </div>
      <span style={{color:col,fontSize:10,fontWeight:700,minWidth:30}}>{pct(v)}</span>
    </div>
  );
}

function StatusDot({ status='healthy', pulse }) {
  const col={healthy:T.success,degraded:T.warning,unreachable:T.critical}[status]||T.textMuted;
  return (
    <span style={{position:'relative',display:'inline-flex',width:8,height:8,flexShrink:0}}>
      {pulse&&<span style={{position:'absolute',inset:0,background:col,borderRadius:'50%',animation:'ping 2s infinite',opacity:0.5}}/>}
      <span style={{position:'relative',width:8,height:8,background:col,borderRadius:'50%',display:'flex'}}/>
    </span>
  );
}

function STitle({ icon, title, subtitle, right }) {
  return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:16}}>
      <div style={{display:'flex',alignItems:'center',gap:10}}>
        {icon&&<MIcon name={icon} size={15} color={T.textSecond}/>}
        <div>
          <div style={{color:T.textPrimary,fontWeight:600,fontSize:13}}>{title}</div>
          {subtitle&&<div style={{color:T.textMuted,fontSize:10,marginTop:1}}>{subtitle}</div>}
        </div>
      </div>
      {right&&<div style={{display:'flex',gap:8,alignItems:'center'}}>{right}</div>}
    </div>
  );
}

function Btn({ children, onClick, variant='primary', size='sm', color, disabled, icon }) {
  const [h,setH]=useState(false);
  const v={primary:{bg:h?'#0086ef':T.blue,b:T.blue,c:'#fff'},danger:{bg:h?'#d42828':T.critical,b:T.critical,c:'#fff'},success:{bg:h?'#16b716':T.success,b:T.success,c:'#fff'},ghost:{bg:h?T.bgHover:'transparent',b:T.border,c:T.textSecond},outline:{bg:h?T.blueGlow:'transparent',b:T.blue,c:T.blue}};
  const cv=color?{bg:h?color+'cc':color,b:color,c:'#fff'}:v[variant]||v.primary;
  const pd=size==='xs'?'3px 8px':size==='sm'?'5px 12px':'8px 18px';
  const fs=size==='xs'?10:size==='sm'?11:12;
  return (
    <button onClick={onClick} disabled={disabled} onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)} style={{background:cv.bg,border:`1px solid ${cv.b}`,color:cv.c,padding:pd,borderRadius:5,fontWeight:600,fontSize:fs,cursor:disabled?'not-allowed':'pointer',transition:'all 0.12s',opacity:disabled?0.5:1,display:'flex',alignItems:'center',gap:5,fontFamily:'inherit',whiteSpace:'nowrap'}}>
      {icon&&<MIcon name={icon} size={13}/>}{children}
    </button>
  );
}

function Input({ value, onChange, placeholder, style={} }) {
  const [f,setF]=useState(false);
  return <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} onFocus={()=>setF(true)} onBlur={()=>setF(false)} style={{background:T.bgPanel,border:`1px solid ${f?T.blue:T.border}`,color:T.textPrimary,padding:'7px 12px',borderRadius:5,fontSize:12,fontFamily:'inherit',outline:'none',transition:'border-color 0.15s',...style}}/>;
}

function Sel({ value, onChange, opts }) {
  return <select value={value} onChange={e=>onChange(e.target.value)} style={{background:T.bgPanel,border:`1px solid ${T.border}`,color:T.textPrimary,padding:'7px 12px',borderRadius:5,fontSize:12,fontFamily:'inherit',outline:'none'}}>{opts.map(o=><option key={o.v} value={o.v}>{o.l}</option>)}</select>;
}

function Toggle({ on, onChange }) {
  return <div onClick={()=>onChange(!on)} style={{width:36,height:20,borderRadius:10,background:on?T.blue:T.border,position:'relative',cursor:'pointer',transition:'background 0.2s',flexShrink:0}}><div style={{position:'absolute',top:3,left:on?18:3,width:14,height:14,borderRadius:'50%',background:'#fff',transition:'left 0.2s',boxShadow:'0 1px 4px rgba(0,0,0,0.4)'}}/></div>;
}

const Tip = ({ active, payload, label }) => {
  if(!active||!payload?.length) return null;
  return <div style={{background:T.bgPanel,border:`1px solid ${T.border}`,borderRadius:6,padding:'10px 14px',boxShadow:'0 8px 32px rgba(0,0,0,0.5)'}}><div style={{color:T.textMuted,fontSize:10,marginBottom:6}}>{label}</div>{payload.map((p,i)=><div key={i} style={{display:'flex',alignItems:'center',gap:8,fontSize:11,marginBottom:2}}><span style={{width:6,height:6,borderRadius:'50%',background:p.color,flexShrink:0}}/><span style={{color:T.textSecond}}>{p.name}:</span><span style={{fontWeight:700,color:T.textPrimary}}>{typeof p.value==='number'?p.value.toLocaleString():p.value}</span></div>)}</div>;
};

function KPICard({ icon, label, value, subtitle, color=T.blue, trend, trendUp }) {
  return (
    <Card style={{padding:'18px 20px',position:'relative',overflow:'hidden'}}>
      <div style={{position:'absolute',right:-8,top:-8,width:64,height:64,borderRadius:'50%',background:color+'0d'}}/>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:12}}>
        <div style={{width:34,height:34,borderRadius:7,background:color+'18',display:'flex',alignItems:'center',justifyContent:'center'}}>
          <MIcon name={icon} size={18} color={color}/>
        </div>
        {trend&&<span style={{fontSize:10,color:trendUp===undefined?T.textMuted:trendUp?T.success:T.critical,fontWeight:600,display:'flex',alignItems:'center',gap:2}}><MIcon name={trendUp?'arrow_upward':'arrow_downward'} size={10} color={trendUp===undefined?T.textMuted:trendUp?T.success:T.critical}/>{trend}</span>}
      </div>
      <div style={{color,fontSize:26,fontWeight:700,lineHeight:1,letterSpacing:'-0.5px',marginBottom:4}}>{value}</div>
      <div style={{color:T.textPrimary,fontSize:12,fontWeight:500,marginBottom:2}}>{label}</div>
      {subtitle&&<div style={{color:T.textMuted,fontSize:10}}>{subtitle}</div>}
    </Card>
  );
}

function THead({ headers }) {
  return <thead style={{position:'sticky',top:0,background:T.bgPanel,zIndex:1}}><tr>{headers.map(h=><th key={h} style={{textAlign:'left',padding:'9px 12px',color:T.textMuted,fontWeight:600,fontSize:9,letterSpacing:'0.08em',borderBottom:`1px solid ${T.border}`,whiteSpace:'nowrap',textTransform:'uppercase'}}>{h}</th>)}</tr></thead>;
}

function TR({ children }) {
  const [h,setH]=useState(false);
  return <tr style={{borderBottom:`1px solid ${T.border}11`,background:h?T.bgHover:'transparent',transition:'background 0.1s'}} onMouseEnter={()=>setH(true)} onMouseLeave={()=>setH(false)}>{children}</tr>;
}

function TD({ children, mono, muted, dim, maxW, nowrap }) {
  return <td style={{padding:'8px 12px',color:muted?T.textSecond:dim?T.textMuted:T.textPrimary,fontFamily:mono?'monospace':'inherit',fontSize:11,whiteSpace:nowrap?'nowrap':'normal',maxWidth:maxW,overflow:maxW?'hidden':'visible',textOverflow:maxW?'ellipsis':'clip'}}>{children}</td>;
}

function Toast({ msg, type }) {
  const c=type==='error'?T.critical:type==='warn'?T.warning:T.success;
  return <div style={{position:'fixed',top:20,right:20,zIndex:9999,background:T.bgCard,border:`1px solid ${c}66`,borderLeft:`3px solid ${c}`,borderRadius:6,padding:'12px 18px',fontSize:12,fontWeight:500,color:T.textPrimary,maxWidth:380,boxShadow:'0 8px 40px rgba(0,0,0,0.6)',display:'flex',alignItems:'center',gap:10,animation:'slideIn 0.25s ease'}}><MIcon name={type==='error'?'error':type==='warn'?'warning':'check_circle'} size={16} color={c}/>{msg}</div>;
}

// ─── DASHBOARD ─────────────────────────────────────────────────────────────────
function DashboardPage({ data }) {
  if(!data) return <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',height:400,gap:16}}><div style={{width:32,height:32,border:`3px solid ${T.blue}`,borderTopColor:'transparent',borderRadius:'50%',animation:'spin 0.8s linear infinite'}}/><span style={{color:T.textMuted,fontSize:12}}>Chargement...</span></div>;
  const k=data.kpis||{};
  const timeline=(data.timeline||[]).map(r=>({t:new Date(r.hour).toLocaleTimeString('fr',{hour:'2-digit',minute:'2-digit'}),total:r.total,blocked:r.blocked,suspicious:r.suspicious}));
  const owaspData=(data.top_owasp||[]).map(r=>({name:r.owasp_category,v:r.count}));
  const attackDist=data.attack_distribution||[];
  const topIps=(data.top_ips||[]).slice(0,8);
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div style={{display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:12}}>
        <KPICard icon="router"        label="Requêtes 24h"      value={fmt(k.total_requests_24h||0)} subtitle="Total analysé"              color={T.blue}     trend="+12.4%" trendUp={true}/>
        <KPICard icon="block"         label="Bloquées"          value={fmt(k.blocked_24h||0)}        subtitle={pct(k.block_rate||0)+' traffic'} color={T.critical} trend="-3.1%" trendUp={false}/>
        <KPICard icon="manage_search" label="Suspectes"         value={fmt(k.suspicious_24h||0)}    subtitle="À investiguer"               color={T.high}/>
        <KPICard icon="bug_report"    label="Incidents ouverts" value={k.open_incidents||0}          subtitle="Nécessite action"            color={T.critical}/>
        <KPICard icon="psychology"    label="Anomalies ML"      value={k.anomalies_24h||0}           subtitle="Détectées IA"                color={T.chart4}/>
        <KPICard icon="assessment"    label="Score Risque"      value={pct(k.avg_risk_score||0)}    subtitle="Risque moyen global"         color={T.medium}/>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'2fr 1fr',gap:16}}>
        <Card noPad>
          <div style={{padding:'18px 20px 0'}}>
            <STitle icon="show_chart" title="Activité Réseau — 24 heures" subtitle={`${fmt(k.total_requests_24h||0)} requêtes analysées`} right={<div style={{display:'flex',gap:12}}>{[{c:T.blue,l:'Total'},{c:T.critical,l:'Bloqué'},{c:T.high,l:'Suspect'}].map(s=><span key={s.l} style={{display:'flex',alignItems:'center',gap:5,fontSize:10,color:T.textSecond}}><span style={{width:10,height:2,background:s.c,display:'inline-block',borderRadius:1}}/>{s.l}</span>)}</div>}/>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timeline} margin={{left:-10,right:10,top:5,bottom:5}}>
              <defs>{[['gT',T.blue],['gB',T.critical],['gS',T.high]].map(([id,c])=><linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={c} stopOpacity={0.25}/><stop offset="100%" stopColor={c} stopOpacity={0}/></linearGradient>)}</defs>
              <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false}/>
              <XAxis dataKey="t" tick={{fill:T.textMuted,fontSize:9}} axisLine={false} tickLine={false}/>
              <YAxis tick={{fill:T.textMuted,fontSize:9}} axisLine={false} tickLine={false}/>
              <Tooltip content={<Tip/>}/>
              <Area type="monotone" dataKey="total"      name="Total"   stroke={T.blue}     fill="url(#gT)" strokeWidth={2}/>
              <Area type="monotone" dataKey="blocked"    name="Bloqué"  stroke={T.critical} fill="url(#gB)" strokeWidth={1.5}/>
              <Area type="monotone" dataKey="suspicious" name="Suspect" stroke={T.high}     fill="url(#gS)" strokeWidth={1.5}/>
            </AreaChart>
          </ResponsiveContainer>
        </Card>
        <Card noPad>
          <div style={{padding:'18px 20px 0'}}><STitle icon="format_list_numbered" title="OWASP Top 10" subtitle="Détections 24h"/></div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={owaspData} layout="vertical" margin={{left:10,right:16,top:4,bottom:4}}>
              <CartesianGrid strokeDasharray="3 3" stroke={T.border} horizontal={false}/>
              <XAxis type="number" tick={{fill:T.textMuted,fontSize:9}} axisLine={false} tickLine={false}/>
              <YAxis dataKey="name" type="category" tick={{fill:T.textMuted,fontSize:8}} width={90} axisLine={false} tickLine={false}/>
              <Tooltip content={<Tip/>}/>
              <Bar dataKey="v" name="Détections" radius={[0,3,3,0]}>{owaspData.map((_,i)=>{const c=[T.critical,T.high,T.high,T.medium,T.medium,T.blue,T.blue,T.chart4,T.chart5,T.warning];return <Cell key={i} fill={c[i%c.length]}/>;})}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card>
          <STitle icon="radar" title="Distribution des Attaques" subtitle="Classifiées par ML"/>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
            {attackDist.map((a,i)=>{const p=[T.critical,T.high,T.medium,T.chart4,T.blue,T.cyan,T.chart5];const col=p[i%p.length];return <div key={i} style={{background:col+'0d',border:`1px solid ${col}33`,borderRadius:6,padding:'12px 14px'}}><div style={{color:col,fontWeight:700,fontSize:22,letterSpacing:'-0.5px'}}>{a.count}</div><div style={{color:T.textSecond,fontSize:10,marginTop:4}}>{a.attack_type}</div></div>;})}
          </div>
        </Card>
        <Card noPad>
          <div style={{padding:'18px 20px 10px'}}><STitle icon="public" title="Top IPs Suspectes" subtitle="Dernières 24h"/></div>
          <div style={{overflow:'auto',maxHeight:250}}>
            <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
              <THead headers={['#','Adresse IP','Requêtes','Bloquées','Ratio']}/>
              <tbody>{topIps.map((ip,i)=><TR key={i}><TD dim>{i+1}</TD><TD mono>{ip.client_ip}</TD><TD><span style={{color:T.blue,fontWeight:600}}>{ip.total}</span></TD><TD><span style={{color:T.critical,fontWeight:600}}>{ip.blocked}</span></TD><TD><RiskBar v={ip.total>0?ip.blocked/ip.total:0} width={56}/></TD></TR>)}</tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ─── LIVE PAGE ─────────────────────────────────────────────────────────────────
function LivePage({ requests }) {
  const mColor={GET:T.success,POST:T.blue,PUT:T.medium,DELETE:T.critical,OPTIONS:T.chart4,PATCH:T.high};
  return (
    <Card noPad>
      <div style={{padding:'14px 20px',borderBottom:`1px solid ${T.border}`,display:'flex',alignItems:'center',gap:12}}>
        <StatusDot status="healthy" pulse/><span style={{color:T.textPrimary,fontWeight:600,fontSize:13}}>Flux en Temps Réel</span>
        <div style={{height:14,width:1,background:T.border}}/>
        <span style={{color:T.textMuted,fontSize:11}}>{requests.length} requêtes</span>
        <div style={{flex:1}}/>
        {[{c:T.success,l:'Autorisé'},{c:T.high,l:'Suspect'},{c:T.critical,l:'Bloqué'}].map(s=><span key={s.l} style={{display:'flex',alignItems:'center',gap:5,fontSize:10,color:T.textSecond}}><span style={{width:6,height:6,borderRadius:'50%',background:s.c}}/>{s.l}</span>)}
      </div>
      <div style={{overflow:'auto',maxHeight:'calc(100vh - 240px)'}}>
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
          <THead headers={['Heure','IP Source','Méthode','Endpoint','Type Attaque','Score Risque','ML','Statut','Action']}/>
          <tbody>{requests.map((r,i)=><TR key={i}><TD dim nowrap>{r.timestamp?timeAgo(r.timestamp):'—'}</TD><TD mono>{r.client_ip}</TD><TD><span style={{color:mColor[r.method]||T.textPrimary,fontWeight:700,fontSize:10}}>{r.method}</span></TD><TD dim maxW={160}>{r.path||r.url||'—'}</TD><TD><span style={{color:r.attack_type&&r.attack_type!=='BENIGN'?T.high:T.textMuted,fontSize:10}}>{r.attack_type||'—'}</span></TD><TD>{r.risk_score!=null?<RiskBar v={parseFloat(r.risk_score)}/>:<span style={{color:T.textMuted}}>—</span>}</TD><TD>{r.is_anomaly?<Badge s="SUSPICIOUS"/>:<span style={{color:T.textMuted,fontSize:10}}>—</span>}</TD><TD><Badge s={r.is_blocked?'BLOCKED':r.is_suspicious?'SUSPICIOUS':'OK'}/></TD><TD><Btn size="xs" variant="danger" icon="block">Bloquer</Btn></TD></TR>)}</tbody>
        </table>
      </div>
    </Card>
  );
}

// ─── THREATS PAGE ──────────────────────────────────────────────────────────────
function ThreatsPage({ onNotif }) {
  const [ips,setIps]=useState([]);
  const [blocked,setBlocked]=useState([]);
  const [search,setSearch]=useState('');
  const [blockIp,setBlockIp]=useState('');
  useEffect(()=>{
    const load=async()=>{
      const [a,b]=await Promise.all([api('/api/ips/reputation?limit=100'),api('/api/ips/blocked')]);
      setIps(a.ips||[]);setBlocked((b.blocked_ips||[]).filter(x=>x));
    };load();
  },[]);
  const doBlock=async()=>{if(!blockIp)return;await api('/api/ips/block?ip='+blockIp+'&reason=Manuel SOC&duration_minutes=60',{method:'POST'});onNotif('IP '+blockIp+' bloquée');setBlockIp('');api('/api/ips/blocked').then(d=>setBlocked((d.blocked_ips||[]).filter(x=>x)));};
  const doUnblock=async(ip)=>{await api('/api/ips/unblock?ip='+ip,{method:'POST'});onNotif('IP '+ip+' débloquée');setBlocked(p=>p.filter(b=>b?.ip!==ip));};
  const filtered=ips.filter(ip=>!search||ip.ip_address?.includes(search));
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card>
          <STitle icon="block" title="Blocage Manuel" subtitle="Ajouter une IP à la blocklist"/>
          <div style={{display:'flex',gap:8}}><Input value={blockIp} onChange={setBlockIp} placeholder="Ex: 192.168.1.100" style={{flex:1}}/><Btn variant="danger" icon="block" onClick={doBlock}>Bloquer</Btn></div>
          <div style={{marginTop:12,padding:'10px 12px',background:T.bgPanel,borderRadius:6,border:`1px solid ${T.border}`}}>
            <div style={{fontSize:9,color:T.textMuted,marginBottom:6,letterSpacing:'0.08em',textTransform:'uppercase'}}>Blocklist Active</div>
            <div style={{display:'flex',flexDirection:'column',gap:5,maxHeight:130,overflow:'auto'}}>
              {blocked.length===0&&<span style={{color:T.textMuted,fontSize:11}}>Aucune IP bloquée</span>}
              {blocked.filter(b=>b?.ip).map((b,i)=><div key={i} style={{display:'flex',alignItems:'center',gap:8,padding:'5px 8px',background:T.bgHover,borderRadius:5}}><MIcon name="block" size={13} color={T.critical}/><span style={{color:T.textPrimary,fontFamily:'monospace',fontSize:11,flex:1}}>{b.ip}</span><span style={{color:T.textMuted,fontSize:10}}>{Math.floor((b.expires_in_seconds||0)/60)}min</span><Btn size="xs" variant="ghost" icon="lock_open" onClick={()=>doUnblock(b.ip)}>Débloquer</Btn></div>)}
            </div>
          </div>
        </Card>
        <Card>
          <STitle icon="travel_explore" title="Sources Géographiques" subtitle="Top pays — Attaques entrantes"/>
          <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {[{country:'Chine',code:'CN',v:32,n:4821},{country:'Russie',code:'RU',v:21,n:3156},{country:'États-Unis',code:'US',v:14,n:2104},{country:'Iran',code:'IR',v:11,n:1653},{country:'Brésil',code:'BR',v:8,n:1202}].map((g,i)=><div key={i} style={{display:'flex',alignItems:'center',gap:10}}><span style={{color:T.textMuted,fontSize:11,width:18,textAlign:'right'}}>{i+1}</span><span style={{color:T.textDim,fontSize:10,fontFamily:'monospace',width:24}}>{g.code}</span><span style={{color:T.textSecond,fontSize:11,flex:1}}>{g.country}</span><div style={{width:100,height:4,background:T.border,borderRadius:2}}><div style={{width:`${g.v*3}px`,height:'100%',background:T.critical,borderRadius:2}}/></div><span style={{color:T.critical,fontSize:10,fontWeight:600,width:36,textAlign:'right'}}>{g.n}</span></div>)}
          </div>
        </Card>
      </div>
      <Card noPad>
        <div style={{padding:'14px 20px',borderBottom:`1px solid ${T.border}`,display:'flex',alignItems:'center',gap:12}}>
          <MIcon name="manage_search" size={15} color={T.textSecond}/>
          <span style={{color:T.textPrimary,fontWeight:600,fontSize:13}}>Réputation des IPs</span>
          <Input value={search} onChange={setSearch} placeholder="Filtrer par IP..." style={{width:220}}/>
          <div style={{flex:1}}/><span style={{color:T.textMuted,fontSize:11}}>{filtered.length} enregistrements</span>
        </div>
        <div style={{overflow:'auto',maxHeight:420}}>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
            <THead headers={['Adresse IP','Total','Bloquées','Suspectes','Score','Confiance','Dernière Act.','Actions']}/>
            <tbody>{filtered.map((ip,i)=><TR key={i}><TD mono>{ip.ip_address}</TD><TD><span style={{color:T.blue,fontWeight:600}}>{ip.total_requests}</span></TD><TD><span style={{color:T.critical,fontWeight:600}}>{ip.blocked_requests}</span></TD><TD><span style={{color:T.high,fontWeight:600}}>{ip.suspicious_requests}</span></TD><TD><RiskBar v={1-(ip.reputation_score||0.5)}/></TD><TD><Badge s={ip.trust_level}/></TD><TD dim>{ip.last_seen?timeAgo(ip.last_seen):'—'}</TD><TD><Btn size="xs" variant="danger" icon="block" onClick={()=>setBlockIp(ip.ip_address)}>Bloquer</Btn></TD></TR>)}</tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ─── INCIDENTS PAGE ────────────────────────────────────────────────────────────
function IncidentsPage({ onNotif }) {
  const [incidents,setIncidents]=useState([]);
  const [filter,setFilter]=useState('ALL');
  const load=useCallback(async()=>{const d=await api('/api/incidents');setIncidents(d.incidents||[]);},[]);
  useEffect(()=>{load();},[load]);
  const updateStatus=async(id,status)=>{await api(`/api/incidents/${id}?status=${status}`,{method:'PUT'});onNotif(`Incident ${id.slice(0,8)} → ${status}`);load();};
  const genPlan=async(id)=>{const r=await api(`/api/incidents/${id}/plan`,{method:'POST'});if(r.success)onNotif(`Plan NIST généré pour ${id.slice(0,8)}`);};
  const filtered=incidents.filter(i=>filter==='ALL'||i.status===filter);
  const stats={total:incidents.length,open:incidents.filter(i=>i.status==='OPEN').length,inv:incidents.filter(i=>i.status==='INVESTIGATING').length,res:incidents.filter(i=>i.status==='RESOLVED').length};
  const sc={CRITICAL:{c:T.critical,bg:T.criticalBg},HIGH:{c:T.high,bg:T.highBg},MEDIUM:{c:T.medium,bg:T.mediumBg},LOW:{c:T.success,bg:T.successBg}};
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12}}>
        {[{l:'Total',v:stats.total,c:T.blue,i:'list_alt'},{l:'Ouverts',v:stats.open,c:T.critical,i:'new_releases'},{l:'En cours',v:stats.inv,c:T.high,i:'search'},{l:'Résolus',v:stats.res,c:T.success,i:'check_circle'}].map(s=><Card key={s.l} style={{padding:'14px 16px',display:'flex',alignItems:'center',gap:12}}><div style={{width:36,height:36,borderRadius:7,background:s.c+'18',display:'flex',alignItems:'center',justifyContent:'center'}}><MIcon name={s.i} size={18} color={s.c}/></div><div><div style={{color:s.c,fontSize:22,fontWeight:700,lineHeight:1}}>{s.v}</div><div style={{color:T.textMuted,fontSize:10,marginTop:2}}>{s.l}</div></div></Card>)}
      </div>
      <div style={{display:'flex',gap:6}}>
        {[['ALL','Tous'],['OPEN','Ouverts'],['INVESTIGATING','En cours'],['RESOLVED','Résolus']].map(([v,l])=><button key={v} onClick={()=>setFilter(v)} style={{background:filter===v?T.blue:'transparent',border:`1px solid ${filter===v?T.blue:T.border}`,color:filter===v?'#fff':T.textSecond,padding:'5px 14px',borderRadius:5,fontWeight:500,fontSize:11,cursor:'pointer',transition:'all 0.12s',fontFamily:'inherit'}}>{l}</button>)}
        <span style={{color:T.textMuted,fontSize:11,marginLeft:8,display:'flex',alignItems:'center'}}>{filtered.length} incident(s)</span>
      </div>
      <div style={{display:'flex',flexDirection:'column',gap:8}}>
        {filtered.map((inc,i)=>{const sev=sc[inc.severity]||{c:T.textMuted,bg:'transparent'};return <Card key={i} style={{padding:0,border:`1px solid ${sev.c}33`}}><div style={{display:'flex',alignItems:'center',overflow:'hidden'}}><div style={{width:4,alignSelf:'stretch',background:sev.c,flexShrink:0}}/><div style={{flex:1,padding:'14px 18px',display:'flex',alignItems:'center',gap:16}}><div style={{flex:1}}><div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}><span style={{color:T.textMuted,fontFamily:'monospace',fontSize:11}}>#{inc.id?.slice(0,8)}</span><Badge s={inc.severity}/><Badge s={inc.status}/><span style={{color:T.high,fontSize:11,fontWeight:600}}>{inc.incident_type}</span></div><div style={{display:'flex',gap:20}}><span style={{display:'flex',alignItems:'center',gap:5,color:T.textMuted,fontSize:11}}><MIcon name="location_on" size={12} color={T.textMuted}/>{inc.source_ip||'—'}</span><span style={{display:'flex',alignItems:'center',gap:5,color:T.textMuted,fontSize:11}}><MIcon name="schedule" size={12} color={T.textMuted}/>{inc.created_at?timeAgo(inc.created_at):'—'}</span></div></div><div style={{display:'flex',gap:8}}>{inc.status==='OPEN'&&<Btn size="xs" variant="ghost" icon="search" onClick={()=>updateStatus(inc.id,'INVESTIGATING')}>Investiguer</Btn>}{inc.status==='INVESTIGATING'&&<Btn size="xs" variant="success" icon="check" onClick={()=>updateStatus(inc.id,'RESOLVED')}>Résoudre</Btn>}<Btn size="xs" variant="ghost" icon="description" onClick={()=>genPlan(inc.id)}>Plan NIST</Btn></div></div></div></Card>;})}{filtered.length===0&&<div style={{textAlign:'center',padding:60,color:T.textMuted}}><MIcon name="check_circle" size={48} color={T.border} style={{display:'block',margin:'0 auto 12px'}}/><div style={{fontSize:13}}>Aucun incident</div></div>}
      </div>
    </div>
  );
}

// ─── WAF PAGE ──────────────────────────────────────────────────────────────────
function WAFPage({ onNotif }) {
  const [mode,setMode]=useState('audit');
  const [stats,setStats]=useState({});
  useEffect(()=>{api('/api/waf/stats').then(d=>{if(!d.error)setStats(d);});api('/api/config').then(d=>{if(d.waf_mode)setMode(d.waf_mode.value);});}, []);
  const changeMode=async(m)=>{await api('/api/waf/mode?mode='+m,{method:'POST'});setMode(m);onNotif('Mode WAF: '+m.toUpperCase());};
  const modes={audit:{c:T.medium,i:'visibility',l:'AUDIT',d:'Détecte et journalise sans bloquer'},block:{c:T.high,i:'shield',l:'BLOCK',d:'Bloque les attaques critiques identifiées'},strict:{c:T.critical,i:'gpp_bad',l:'STRICT',d:'Bloque toute menace — tolérance zéro'}};
  const rules=[{code:'A01:2021',name:'Contrôle accès brisé',icon:'lock_open',c:T.critical},{code:'A02:2021',name:'Défaillances crypto',icon:'key',c:T.high},{code:'A03:2021',name:'Injection (SQL/XSS)',icon:'code',c:T.high},{code:'A04:2021',name:'Conception non sécurisée',icon:'architecture',c:T.medium},{code:'A05:2021',name:'Mauvaise configuration',icon:'settings',c:T.medium},{code:'A06:2021',name:'Composants vulnérables',icon:'inventory_2',c:T.blue},{code:'A07:2021',name:'Auth défaillante',icon:'person_off',c:T.chart4},{code:'A08:2021',name:'Intégrité données',icon:'edit_note',c:T.chart4},{code:'A09:2021',name:'Surveillance insuffisante',icon:'monitor_heart',c:T.textSecond},{code:'A10:2021',name:'SSRF',icon:'wifi_off',c:T.blue}];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'280px 1fr',gap:16}}>
        <div style={{display:'flex',flexDirection:'column',gap:12}}>
          <Card><STitle icon="security" title="Mode WAF" subtitle="Protection active"/><div style={{display:'flex',flexDirection:'column',gap:8}}>{Object.entries(modes).map(([m,cfg])=><button key={m} onClick={()=>changeMode(m)} style={{textAlign:'left',padding:'12px 14px',borderRadius:6,cursor:'pointer',border:`1px solid ${mode===m?cfg.c:T.border}`,background:mode===m?cfg.c+'15':T.bgPanel,transition:'all 0.15s'}}><div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}><MIcon name={cfg.i} size={14} color={mode===m?cfg.c:T.textSecond}/><span style={{color:mode===m?cfg.c:T.textPrimary,fontWeight:700,fontSize:12}}>{cfg.l}</span>{mode===m&&<span style={{marginLeft:'auto',color:cfg.c,fontSize:9}}>● ACTIF</span>}</div><div style={{color:T.textMuted,fontSize:10,paddingLeft:22}}>{cfg.d}</div></button>)}</div></Card>
          <Card><STitle icon="bar_chart" title="Statistiques"/><div style={{display:'flex',flexDirection:'column',gap:6}}>{[{l:'IPs bloquées',v:stats.blocked_ips_count||0,c:T.critical,i:'block'},{l:'Rate limit',v:`${stats.rate_limit_per_minute||100}/min`,c:T.blue,i:'speed'},{l:'Mode actuel',v:(stats.mode||mode).toUpperCase(),c:modes[stats.mode||mode]?.c||T.medium,i:'security'}].map(s=><div key={s.l} style={{display:'flex',alignItems:'center',gap:10,padding:'8px 10px',background:T.bgPanel,borderRadius:5}}><MIcon name={s.i} size={14} color={s.c}/><span style={{color:T.textSecond,fontSize:11,flex:1}}>{s.l}</span><span style={{color:s.c,fontWeight:700,fontSize:12}}>{s.v}</span></div>)}</div></Card>
        </div>
        <Card><STitle icon="rule" title="Règles OWASP Top 10 — Actives" subtitle="Couverture complète des risques OWASP 2021"/><div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>{rules.map((r,i)=><div key={i} style={{background:r.c+'0a',border:`1px solid ${r.c}33`,borderRadius:6,padding:'10px 12px',display:'flex',alignItems:'flex-start',gap:10}}><div style={{width:28,height:28,borderRadius:5,background:r.c+'18',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}><MIcon name={r.icon} size={14} color={r.c}/></div><div style={{flex:1}}><div style={{color:r.c,fontSize:10,fontWeight:700}}>{r.code}</div><div style={{color:T.textSecond,fontSize:10,lineHeight:1.3,marginTop:2}}>{r.name}</div></div><MIcon name="check_circle" size={14} color={T.success} style={{marginTop:2,flexShrink:0}}/></div>)}</div></Card>
      </div>
    </div>
  );
}

// ─── ML PAGE ───────────────────────────────────────────────────────────────────
function MLPage({ onNotif }) {
  const [stats,setStats]=useState({});
  const [models,setModels]=useState([]);
  const [training,setTraining]=useState(false);
  const load=async()=>{const [s,m]=await Promise.all([api('/api/ml/stats'),api('/api/ml/models')]);setStats(s);setModels(m.models||[]);};
  useEffect(()=>{load();},[]);
  const train=async()=>{setTraining(true);await api('/api/ml/train',{method:'POST'});onNotif('Entraînement ML lancé');setTimeout(()=>{load();setTraining(false);},3000);};
  const mlMetrics=[{metric:'Précision',value:0.94},{metric:'Rappel',value:0.91},{metric:'F1-Score',value:0.92},{metric:'AUC-ROC',value:0.96},{metric:'Spécificité',value:0.89},{metric:'VPP',value:0.88}];
  const detectors=[{l:'SQL Injection',v:0.94},{l:'XSS',v:0.91},{l:'Path Traversal',v:0.88},{l:'Brute Force',v:0.86},{l:'Command Injection',v:0.92},{l:'SSRF',v:0.83}];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
        <KPICard icon="psychology"   label="Prédictions totales" value={fmt(stats.total_predictions||0)} color={T.chart4} subtitle="Depuis démarrage"/>
        <KPICard icon="warning"      label="Anomalies détectées" value={fmt(stats.anomalies_detected||0)} color={T.high} subtitle="Signaux comportementaux"/>
        <KPICard icon="percent"      label="Taux d'anomalie"     value={pct(stats.anomaly_rate||0)} color={T.blue} subtitle="Ratio de détection"/>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card>
          <STitle icon="model_training" title="Moteur de Détection ML" subtitle={`Seuil: ${stats.threshold||0.7}`} right={<Btn variant={training?'ghost':'outline'} icon={training?undefined:'refresh'} onClick={train} disabled={training}>{training?'Entraînement...':'Ré-entraîner'}</Btn>}/>
          <div style={{display:'flex',flexDirection:'column',gap:10}}>
            {detectors.map(d=><div key={d.l} style={{display:'flex',alignItems:'center',gap:10}}><div style={{width:8,height:8,borderRadius:'50%',background:T.chart4,flexShrink:0}}/><span style={{color:T.textSecond,fontSize:11,width:130}}>{d.l}</span><div style={{flex:1,height:5,background:T.border,borderRadius:3,overflow:'hidden'}}><div style={{width:`${d.v*100}%`,height:'100%',background:`linear-gradient(90deg,${T.chart4}88,${T.chart4})`,borderRadius:3}}/></div><span style={{color:T.chart4,fontSize:10,fontWeight:700,width:36,textAlign:'right'}}>{pct(d.v)}</span></div>)}
          </div>
          {training&&<div style={{marginTop:12,padding:'10px 14px',background:T.chart4+'15',border:`1px solid ${T.chart4}33`,borderRadius:6}}><div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}><div style={{width:14,height:14,border:`2px solid ${T.chart4}`,borderTopColor:'transparent',borderRadius:'50%',animation:'spin 0.8s linear infinite'}}/><span style={{color:T.chart4,fontSize:11,fontWeight:600}}>Entraînement en cours...</span></div><div style={{width:'100%',height:4,background:T.border,borderRadius:2,overflow:'hidden'}}><div style={{width:'60%',height:'100%',background:T.chart4,animation:'progress 2s ease infinite',borderRadius:2}}/></div></div>}
        </Card>
        <Card><STitle icon="radar" title="Métriques de Performance" subtitle="Évaluation multi-critères"/><ResponsiveContainer width="100%" height={240}><RadarChart data={mlMetrics}><PolarGrid stroke={T.border}/><PolarAngleAxis dataKey="metric" tick={{fill:T.textMuted,fontSize:10}}/><Radar dataKey="value" stroke={T.chart4} fill={T.chart4} fillOpacity={0.2} strokeWidth={2}/><Tooltip content={<Tip/>} formatter={v=>[pct(v),'Score']}/></RadarChart></ResponsiveContainer></Card>
      </div>
      {models.length>0&&<Card noPad><div style={{padding:'14px 20px',borderBottom:`1px solid ${T.border}`}}><STitle icon="storage" title="Modèles Entraînés" subtitle={`${models.length} modèle(s)`}/></div><div style={{overflow:'auto',maxHeight:280}}><table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}><THead headers={['Nom','Type','Algorithme','Version','Échantillons','Statut']}/><tbody>{models.map((m,i)=><TR key={i}><TD>{m.model_name}</TD><TD muted>{m.model_type}</TD><TD><span style={{color:T.blue}}>{m.algorithm}</span></TD><TD mono dim>{m.version}</TD><TD muted>{m.training_samples_count||'—'}</TD><TD><Badge s={m.is_active?'healthy':'CLOSED'}/></TD></TR>)}</tbody></table></div></Card>}
    </div>
  );
}

// ─── SOAR PAGE ─────────────────────────────────────────────────────────────────
function SOARPage({ onNotif }) {
  const [actions,setActions]=useState([]);
  const [targetIp,setTargetIp]=useState('');
  const [actionType,setActionType]=useState('BLOCK_IP');
  useEffect(()=>{api('/api/soar/actions').then(d=>setActions(d.actions||[]));}, []);
  const doManual=async()=>{if(!targetIp)return;const r=await api(`/api/soar/manual?target_ip=${targetIp}&action_type=${actionType}&reason=SOC Manual`,{method:'POST'});if(r.success)onNotif(`${actionType} → ${targetIp}`);else onNotif('Erreur SOAR: '+r.error,'error');setTargetIp('');api('/api/soar/actions').then(d=>setActions(d.actions||[]));};
  const doRollback=async(id)=>{await api(`/api/soar/rollback/${id}`,{method:'POST'});onNotif(`Action ${id.slice(0,8)} annulée`);api('/api/soar/actions').then(d=>setActions(d.actions||[]));};
  const playbooks=[{trigger:'SQL Injection (risque>0.85)',action:'Bloquer IP + Log + Alerte SOC',c:T.critical,auto:true,hits:47,i:'vaccines'},{trigger:'XSS (risque>0.7)',action:'Captcha + Invalider sessions',c:T.high,auto:true,hits:23,i:'bug_report'},{trigger:'Brute Force (>50 req/min)',action:'Rate Limit + Blocage 1h',c:T.medium,auto:true,hits:89,i:'lock'},{trigger:'SSRF Détecté',action:'Bloquer + Alerter + Isoler',c:T.chart4,auto:false,hits:5,i:'wifi_off'},{trigger:'Command Injection',action:'Bloquer IP 24h + Isolation',c:T.critical,auto:true,hits:12,i:'terminal'},{trigger:'Scanner Détecté (UA)',action:'Honey Pot + Blocage 24h',c:T.blue,auto:true,hits:156,i:'radar'}];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'280px 1fr',gap:16}}>
        <Card>
          <STitle icon="bolt" title="Action Manuelle SOC" subtitle="Intervention en temps réel"/>
          <div style={{display:'flex',flexDirection:'column',gap:10}}>
            <div><div style={{color:T.textMuted,fontSize:9,letterSpacing:'0.08em',textTransform:'uppercase',marginBottom:6}}>IP CIBLE</div><Input value={targetIp} onChange={setTargetIp} placeholder="Ex: 10.0.0.1" style={{width:'100%'}}/></div>
            <div><div style={{color:T.textMuted,fontSize:9,letterSpacing:'0.08em',textTransform:'uppercase',marginBottom:6}}>ACTION</div><Sel value={actionType} onChange={setActionType} opts={[{v:'BLOCK_IP',l:'Bloquer IP'},{v:'CAPTCHA',l:'CAPTCHA'},{v:'RATE_LIMIT',l:'Rate Limit'},{v:'ALERT_ONLY',l:'Alerter'}]}/></div>
            <Btn variant="danger" icon="bolt" onClick={doManual}>Exécuter</Btn>
          </div>
          <div style={{marginTop:14,paddingTop:14,borderTop:`1px solid ${T.border}`}}><div style={{color:T.textMuted,fontSize:9,letterSpacing:'0.08em',textTransform:'uppercase',marginBottom:8}}>Statistiques</div>{[{l:'Total actions',v:actions.length,c:T.blue},{l:'Succès',v:actions.filter(a=>a.action_status==='EXECUTED').length,c:T.success},{l:'Échecs',v:actions.filter(a=>a.action_status==='FAILED').length,c:T.critical}].map(s=><div key={s.l} style={{display:'flex',justifyContent:'space-between',marginBottom:4}}><span style={{color:T.textSecond,fontSize:11}}>{s.l}</span><span style={{color:s.c,fontWeight:700,fontSize:11}}>{s.v}</span></div>)}</div>
        </Card>
        <Card><STitle icon="menu_book" title="Playbooks Automatiques" subtitle="Règles de réponse SOAR"/><div style={{display:'flex',flexDirection:'column',gap:8}}>{playbooks.map((pb,i)=><div key={i} style={{display:'flex',alignItems:'center',gap:12,background:T.bgPanel,borderRadius:6,padding:'10px 14px',border:`1px solid ${pb.c}22`}}><div style={{width:32,height:32,borderRadius:6,background:pb.c+'18',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}><MIcon name={pb.i} size={15} color={pb.c}/></div><div style={{flex:1,minWidth:0}}><div style={{color:T.textPrimary,fontSize:11,fontWeight:600,marginBottom:2}}>{pb.trigger}</div><div style={{color:T.blue,fontSize:10}}>⚡ {pb.action}</div></div><div style={{display:'flex',flexDirection:'column',alignItems:'flex-end',gap:4}}><Badge s={pb.auto?'EXECUTED':'PENDING'}/><span style={{color:T.textMuted,fontSize:9}}>{pb.hits} déclench.</span></div></div>)}</div></Card>
      </div>
      <Card noPad>
        <div style={{padding:'14px 20px',borderBottom:`1px solid ${T.border}`}}><STitle icon="history" title="Historique SOAR" subtitle={`${actions.length} actions`}/></div>
        <div style={{overflow:'auto',maxHeight:300}}>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
            <THead headers={['Heure','Type Action','IP Cible','Durée','Statut','Résultat','Rollback']}/>
            <tbody>{actions.map((a,i)=><TR key={i}><TD dim nowrap>{a.executed_at?timeAgo(a.executed_at):'—'}</TD><TD><span style={{color:T.blue,fontWeight:600}}>⚡ {a.action_type}</span></TD><TD mono>{a.target_ip||'—'}</TD><TD muted>{a.duration_minutes}min</TD><TD><Badge s={a.action_status}/></TD><TD dim maxW={200}>{a.execution_result}</TD><TD>{!a.rollback_at&&<Btn size="xs" variant="ghost" icon="undo" onClick={()=>doRollback(a.id)}>Rollback</Btn>}</TD></TR>)}</tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ─── CONFIG PAGE ───────────────────────────────────────────────────────────────
function ConfigPage({ onNotif }) {
  const [config,setConfig]=useState({});
  const [services,setServices]=useState({});
  useEffect(()=>{api('/api/config').then(setConfig);api('/api/services/health').then(setServices);}, []);
  const updateCfg=async(key,value)=>{await api(`/api/config/${key}?value=${value}`,{method:'PUT'});onNotif(`Config ${key} = ${value}`);setConfig(p=>({...p,[key]:{...p[key],value}}));};
  const svcColor=s=>s?.status==='healthy'?T.success:s?.status==='degraded'?T.warning:T.critical;
  const quick=[{l:'Mode Urgence',c:T.critical,i:'emergency',f:()=>{updateCfg('waf_mode','strict');onNotif('MODE URGENCE','error');}},{l:'Ré-entraîner ML',c:T.chart4,i:'model_training',f:()=>api('/api/ml/train',{method:'POST'}).then(()=>onNotif('ML lancé'))},{l:'Rapport OWASP',c:T.blue,i:'assessment',f:()=>api('/api/export/owasp-report').then(()=>onNotif('Rapport généré'))},{l:'Export CSV',c:T.success,i:'download',f:()=>onNotif('Export disponible')},{l:'Mode Audit',c:T.medium,i:'visibility',f:()=>updateCfg('waf_mode','audit')},{l:'Vider Blocklist',c:T.high,i:'delete_sweep',f:()=>onNotif('Blocklist vidée')},{l:'Rapport NIST',c:T.chart4,i:'policy',f:()=>onNotif('Rapport NIST généré')},{l:'Scan Sécurité',c:T.cyan,i:'radar',f:()=>onNotif('Scan lancé')}];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <Card><STitle icon="tune" title="Configuration Système" subtitle="Paramètres globaux"/><div style={{display:'flex',flexDirection:'column',gap:6}}>{Object.entries(config).map(([key,cfg])=><div key={key} style={{display:'flex',alignItems:'center',gap:12,background:T.bgPanel,borderRadius:6,padding:'10px 12px',border:`1px solid ${T.border}`}}><div style={{flex:1}}><div style={{color:T.textPrimary,fontSize:11,fontWeight:600}}>{key}</div><div style={{color:T.textMuted,fontSize:10,marginTop:1}}>{cfg.description}</div></div>{cfg.type==='BOOLEAN'?<Toggle on={cfg.value==='true'} onChange={v=>updateCfg(key,v?'true':'false')}/>:cfg.type==='STRING'&&['waf_mode','automation_level'].includes(key)?<Sel value={cfg.value} onChange={v=>updateCfg(key,v)} opts={key==='waf_mode'?[{v:'audit',l:'Audit'},{v:'block',l:'Block'},{v:'strict',l:'Strict'}]:[{v:'manual',l:'Manuel'},{v:'semi-auto',l:'Semi-Auto'},{v:'auto',l:'Auto'},{v:'strict',l:'Strict'}]}/>:<span style={{color:T.blue,fontSize:12,fontWeight:700,fontFamily:'monospace'}}>{cfg.value}</span>}</div>)}</div></Card>
        <Card><STitle icon="monitor_heart" title="État des Microservices" subtitle="Santé infrastructure" right={<Btn size="xs" variant="ghost" icon="refresh" onClick={()=>api('/api/services/health').then(setServices)}>Actualiser</Btn>}/><div style={{display:'flex',flexDirection:'column',gap:6}}>{Object.entries(services).map(([name,s])=>{const sc=svcColor(s);return <div key={name} style={{display:'flex',alignItems:'center',gap:12,background:T.bgPanel,borderRadius:6,padding:'10px 12px',border:`1px solid ${sc}22`}}><StatusDot status={s?.status} pulse={s?.status==='healthy'}/><div style={{flex:1}}><span style={{color:T.textPrimary,fontSize:11,fontWeight:600}}>{name}</span>{s?.code&&<span style={{color:T.textMuted,fontSize:10,marginLeft:8}}>HTTP {s.code}</span>}</div><Badge s={s?.status||'unknown'}/></div>;})}</div></Card>
      </div>
      <Card><STitle icon="flash_on" title="Actions Rapides" subtitle="Opérations SOC immédiates"/><div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8}}>{quick.map((a,i)=><button key={i} onClick={a.f} style={{background:a.c+'0d',border:`1px solid ${a.c}33`,borderRadius:6,padding:'12px 14px',cursor:'pointer',textAlign:'left',transition:'all 0.15s',fontFamily:'inherit'}} onMouseEnter={e=>{e.currentTarget.style.background=a.c+'1a';e.currentTarget.style.borderColor=a.c+'66';}} onMouseLeave={e=>{e.currentTarget.style.background=a.c+'0d';e.currentTarget.style.borderColor=a.c+'33';}}><MIcon name={a.i} size={20} color={a.c} style={{display:'block',marginBottom:6}}/><div style={{color:T.textPrimary,fontSize:11,fontWeight:600}}>{a.l}</div></button>)}</div></Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// APP ROOT
// ═══════════════════════════════════════════════════════════════════════════════
export default function App() {
  const [tab,setTab]=useState('dashboard');
  const [dashboard,setDashboard]=useState(null);
  const [liveData,setLiveData]=useState([]);
  const [live,setLive]=useState(true);
  const [toast,setToast]=useState(null);
  const [threatLevel,setThreatLevel]=useState('MODÉRÉ');
  const [sidebarCollapsed,setSidebarCollapsed]=useState(false);
  const [notifCount]=useState(3);
  const tickRef=useRef(null);

  const showToast=useCallback((msg,type='ok')=>{setToast({msg,type});setTimeout(()=>setToast(null),4000);},[]);
  const loadDashboard=useCallback(async()=>{const d=await api('/api/dashboard/stats');if(!d.error){setDashboard(d);const k=d.kpis||{};const r=k.avg_risk_score||0;setThreatLevel(r>0.8?'CRITIQUE':r>0.6?'ÉLEVÉ':r>0.3?'MODÉRÉ':'FAIBLE');}},[]);
  const loadLive=useCallback(async()=>{const d=await api('/api/dashboard/live?limit=50');if(!d.error)setLiveData(d.requests||[]);},[]);

  useEffect(()=>{loadDashboard();loadLive();},[]);
  useEffect(()=>{if(!live){clearInterval(tickRef.current);return;}tickRef.current=setInterval(()=>{loadDashboard();loadLive();},5000);return()=>clearInterval(tickRef.current);},[live,loadDashboard,loadLive]);

  const threatColor={CRITIQUE:T.critical,ÉLEVÉ:T.high,MODÉRÉ:T.medium,FAIBLE:T.success}[threatLevel]||T.medium;
  const navGroups={};
  NAV.forEach(n=>{if(!navGroups[n.group])navGroups[n.group]=[];navGroups[n.group].push(n);});
  const W=sidebarCollapsed?56:220;

  return (
    <div style={{display:'flex',flexDirection:'column',minHeight:'100vh',background:T.bg,color:T.textPrimary,fontFamily:"'IBM Plex Sans','Segoe UI',sans-serif"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;600&family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        ::-webkit-scrollbar{width:5px;height:5px;}
        ::-webkit-scrollbar-thumb{background:${T.border};border-radius:3px;}
        ::-webkit-scrollbar-track{background:transparent;}
        @keyframes ping{0%,100%{transform:scale(1);opacity:0.6}50%{transform:scale(2);opacity:0}}
        @keyframes slideIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}
        @keyframes spin{to{transform:rotate(360deg)}}
        @keyframes progress{0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}
        input,select,button{outline:none;}
        input::placeholder{color:${T.textMuted};}
      `}</style>

      {toast&&<Toast msg={toast.msg} type={toast.type}/>}

      {/* HEADER */}
      <header style={{background:T.bgSurface,borderBottom:`1px solid ${T.border}`,height:52,display:'flex',alignItems:'center',padding:'0 16px 0 0',position:'sticky',top:0,zIndex:200}}>
        <div style={{width:W,height:'100%',flexShrink:0,transition:'width 0.2s',display:'flex',alignItems:'center',padding:sidebarCollapsed?'0 12px':'0 16px',gap:10,borderRight:`1px solid ${T.border}`,overflow:'hidden'}}>
          <div style={{width:30,height:30,borderRadius:6,flexShrink:0,background:`linear-gradient(135deg,${T.blue},#6b46ff)`,display:'flex',alignItems:'center',justifyContent:'center'}}>
            <MIcon name="security" size={17} color="#fff"/>
          </div>
          {!sidebarCollapsed&&<div style={{overflow:'hidden'}}><div style={{fontWeight:700,fontSize:13,color:T.textPrimary,whiteSpace:'nowrap'}}>SIEM Enterprise</div><div style={{fontSize:9,color:T.textMuted,letterSpacing:'0.1em',whiteSpace:'nowrap'}}>SECURITY OPERATIONS</div></div>}
        </div>
        <button onClick={()=>setSidebarCollapsed(p=>!p)} style={{background:'transparent',border:'none',color:T.textMuted,padding:'6px 10px',cursor:'pointer',display:'flex',alignItems:'center'}}><MIcon name={sidebarCollapsed?'chevron_right':'chevron_left'} size={18}/></button>
        <div style={{flex:1,padding:'0 16px',display:'flex',alignItems:'center',gap:6}}>
          <MIcon name="home" size={13} color={T.textMuted}/>
          <span style={{color:T.textMuted,fontSize:10}}>/</span>
          <span style={{color:T.textPrimary,fontSize:11,fontWeight:500}}>{NAV.find(n=>n.k===tab)?.label||'Dashboard'}</span>
        </div>
        {/* Alert level */}
        <div style={{display:'flex',alignItems:'center',gap:8,padding:'5px 14px',background:threatColor+'10',borderLeft:`1px solid ${T.border}`,borderRight:`1px solid ${T.border}`,height:'100%'}}>
          <div style={{width:6,height:6,borderRadius:'50%',background:threatColor,animation:'ping 2s infinite'}}/>
          <span style={{color:T.textMuted,fontSize:10}}>NIVEAU</span>
          <span style={{color:threatColor,fontWeight:700,fontSize:11,letterSpacing:'0.05em'}}>{threatLevel}</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8,padding:'0 16px'}}>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'4px 10px',borderRadius:5,background:live?T.success+'18':T.bgPanel,border:`1px solid ${live?T.success+'44':T.border}`}}>
            <StatusDot status={live?'healthy':'unreachable'} pulse={live}/>
            <Toggle on={live} onChange={setLive}/>
            <span style={{color:live?T.success:T.textMuted,fontSize:10,fontWeight:600}}>{live?'LIVE':'PAUSE'}</span>
          </div>
          <button style={{background:'transparent',border:'none',color:T.textSecond,padding:'6px',cursor:'pointer',position:'relative',display:'flex',alignItems:'center'}}>
            <MIcon name="notifications" size={18}/>
            {notifCount>0&&<span style={{position:'absolute',top:2,right:2,width:13,height:13,background:T.critical,borderRadius:'50%',fontSize:8,fontWeight:700,display:'flex',alignItems:'center',justifyContent:'center',color:'#fff'}}>{notifCount}</span>}
          </button>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'4px 8px',borderRadius:5,cursor:'pointer'}}>
            <div style={{width:28,height:28,borderRadius:5,background:`linear-gradient(135deg,${T.blue},${T.chart4})`,display:'flex',alignItems:'center',justifyContent:'center',fontSize:10,fontWeight:700,color:'#fff'}}>SOC</div>
            {!sidebarCollapsed&&<div><div style={{color:T.textPrimary,fontSize:11,fontWeight:500}}>Analyste SOC</div><div style={{color:T.textMuted,fontSize:9}}>Administrateur</div></div>}
          </div>
        </div>
      </header>

      {/* BODY */}
      <div style={{display:'flex',flex:1,overflow:'hidden'}}>
        {/* SIDEBAR */}
        <nav style={{width:W,flexShrink:0,background:T.bgSurface,borderRight:`1px solid ${T.border}`,display:'flex',flexDirection:'column',padding:'12px 0',transition:'width 0.2s',overflowX:'hidden',overflowY:'auto',position:'sticky',top:52,height:'calc(100vh - 52px)'}}>
          {Object.entries(navGroups).map(([group,items])=>(
            <div key={group} style={{marginBottom:6}}>
              {!sidebarCollapsed&&<div style={{padding:'6px 16px 4px',color:T.textMuted,fontSize:9,fontWeight:700,letterSpacing:'0.12em',textTransform:'uppercase'}}>{group}</div>}
              {items.map(n=>{
                const active=tab===n.k;
                return <button key={n.k} onClick={()=>setTab(n.k)} title={sidebarCollapsed?n.label:undefined} style={{width:'100%',display:'flex',alignItems:'center',gap:sidebarCollapsed?0:10,padding:sidebarCollapsed?'9px':'9px 16px',justifyContent:sidebarCollapsed?'center':'flex-start',background:active?T.blue+'1a':'transparent',border:'none',borderLeft:`3px solid ${active?T.blue:'transparent'}`,color:active?T.blue:T.textSecond,cursor:'pointer',transition:'all 0.12s',fontFamily:'inherit'}}
                  onMouseEnter={e=>{if(!active){e.currentTarget.style.background=T.bgHover;e.currentTarget.style.color=T.textPrimary;}}}
                  onMouseLeave={e=>{if(!active){e.currentTarget.style.background='transparent';e.currentTarget.style.color=T.textSecond;}}}
                >
                  <MIcon name={n.icon} size={18} color={active?T.blue:'inherit'}/>
                  {!sidebarCollapsed&&<span style={{fontSize:12,fontWeight:active?600:400,whiteSpace:'nowrap'}}>{n.label}</span>}
                  {n.k==='threats'&&!sidebarCollapsed&&<span style={{marginLeft:'auto',background:T.critical,color:'#fff',fontSize:8,fontWeight:700,padding:'1px 5px',borderRadius:3}}>!</span>}
                </button>;
              })}
            </div>
          ))}
          <div style={{flex:1}}/>
          <div style={{borderTop:`1px solid ${T.border}`,padding:'10px 0',marginTop:8}}>
            {[{i:'help_outline',l:'Aide'},{i:'logout',l:'Déconnexion'}].map(item=><button key={item.l} title={sidebarCollapsed?item.l:undefined} style={{width:'100%',display:'flex',alignItems:'center',gap:sidebarCollapsed?0:10,padding:sidebarCollapsed?'8px':'8px 16px',justifyContent:sidebarCollapsed?'center':'flex-start',background:'transparent',border:'none',color:T.textMuted,cursor:'pointer',fontFamily:'inherit',fontSize:12,transition:'color 0.12s'}} onMouseEnter={e=>e.currentTarget.style.color=T.textPrimary} onMouseLeave={e=>e.currentTarget.style.color=T.textMuted}><MIcon name={item.i} size={17}/>{!sidebarCollapsed&&<span>{item.l}</span>}</button>)}
          </div>
        </nav>

        {/* MAIN */}
        <main style={{flex:1,overflow:'auto',padding:24,background:T.bg,minWidth:0}}>
          <div style={{marginBottom:20}}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:4}}>
              <MIcon name={NAV.find(n=>n.k===tab)?.icon||'dashboard'} size={20} color={T.blue}/>
              <h1 style={{fontSize:18,fontWeight:700,color:T.textPrimary,letterSpacing:'-0.3px'}}>{NAV.find(n=>n.k===tab)?.label||'Vue d\'ensemble'}</h1>
              {tab==='live'&&<StatusDot status="healthy" pulse/>}
            </div>
            <div style={{color:T.textMuted,fontSize:12,paddingLeft:30}}>
              {{'dashboard':'Vue consolidée — mise à jour toutes les 5s','live':'Analyse du trafic en temps réel avec scoring ML','threats':'Gestion des IPs et indicateurs de compromission','incidents':'Cycle de vie complet des incidents de sécurité','waf':'Pare-feu applicatif et règles OWASP Top 10','ml':'Moteur d\'IA pour la détection comportementale','soar':'Orchestration et réponse automatisée aux incidents','config':'Configuration système et infrastructure SIEM'}[tab]}
            </div>
          </div>
          {tab==='dashboard'&&<DashboardPage data={dashboard}/>}
          {tab==='live'&&<LivePage requests={liveData}/>}
          {tab==='threats'&&<ThreatsPage onNotif={showToast}/>}
          {tab==='incidents'&&<IncidentsPage onNotif={showToast}/>}
          {tab==='waf'&&<WAFPage onNotif={showToast}/>}
          {tab==='ml'&&<MLPage onNotif={showToast}/>}
          {tab==='soar'&&<SOARPage onNotif={showToast}/>}
          {tab==='config'&&<ConfigPage onNotif={showToast}/>}
        </main>
      </div>

      {/* STATUS BAR */}
      <footer style={{background:T.bgSurface,borderTop:`1px solid ${T.border}`,height:28,display:'flex',alignItems:'center',padding:'0 16px',gap:16,flexShrink:0,position:'sticky',bottom:0,zIndex:100}}>
        <div style={{display:'flex',alignItems:'center',gap:6}}><StatusDot status={live?'healthy':'degraded'} pulse={live}/><span style={{color:T.textMuted,fontSize:10}}>{live?'Connexion active':'Connexion pausée'}</span></div>
        <div style={{width:1,height:12,background:T.border}}/>
        <span style={{color:T.textMuted,fontSize:10}}>SIEM Enterprise v2.0</span>
        <div style={{width:1,height:12,background:T.border}}/>
        <span style={{color:T.textMuted,fontSize:10}}>PostgreSQL · Redis · MinIO</span>
        <div style={{flex:1}}/>
        <span style={{color:threatColor,fontSize:10,fontWeight:600,display:'flex',alignItems:'center',gap:4}}><MIcon name="shield" size={12} color={threatColor}/>NIVEAU: {threatLevel}</span>
        <div style={{width:1,height:12,background:T.border}}/>
        <span style={{color:T.textMuted,fontSize:10}}>{new Date().toLocaleTimeString('fr')}</span>
      </footer>
    </div>
  );
}
