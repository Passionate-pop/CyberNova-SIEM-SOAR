import { useState, useEffect, useCallback } from 'react';
import { Brain, Target, Server, ChevronDown, AlertTriangle } from 'lucide-react';
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';
import { Card } from '../components/ui/Card';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { Timeline } from '../components/ui/Timeline';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { useFetch } from '../hooks/useFetch';
import { fetchIncidents, fetchAIAnalysis } from '../services/api';
import { cn } from '../utils/cn';

export function AIInvestigationPage() {
  const { data: incidents, loading: incidentsLoading } = useFetch(
    useCallback(() => fetchIncidents(), [])
  );
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');

  useEffect(() => {
    if (incidents && incidents.length > 0 && !selectedIncidentId) {
      setSelectedIncidentId(incidents[0].incident_id);
    }
  }, [incidents]);

  const { data: analysis, loading: analysisLoading } = useFetch(
    useCallback(() => selectedIncidentId ? fetchAIAnalysis(selectedIncidentId) : Promise.resolve(null), [selectedIncidentId]),
    [selectedIncidentId]
  );

  if (incidentsLoading) return <LoadingSpinner />;

  if (!incidents || incidents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-6">
        <div className="text-center space-y-4">
          <AlertTriangle size={64} className="text-amber-400 mx-auto" />
          <h3 className="text-xl font-semibold text-cyber-text">No Incidents Available</h3>
          <p className="text-sm text-cyber-muted max-w-md">
            There are no incidents to investigate. Incidents will appear here
            when security alerts are correlated into incidents.
          </p>
          <p className="text-xs text-cyber-accent max-w-md">
            Go to Dashboard → Seed Demo Data or Simulate Attack to populate the system.
          </p>
        </div>
      </div>
    );
  }

  if (analysisLoading) return <LoadingSpinner />;

  const analysisData = analysis || {
    summary: 'Select an incident to see AI analysis.',
    attack_narrative: 'No analysis available.',
    risk_assessment: 'Select an incident to view risk assessment.',
    recommended_actions: [],
    confidence: 0,
    timeline_reconstruction: [],
    mitre_techniques: [],
    affected_assets: [],
  };

  const radarSubjects = ['Persistence', 'Lateral Movement', 'Exfiltration', 'Privilege Escalation', 'Evasion', 'Impact'];
  const radarData = analysisData.threat_profile ? radarSubjects.map(subject => ({
    subject,
    score: analysisData.threat_profile![subject] || 0,
  })) : radarSubjects.map(subject => ({
    subject,
    score: 0,
  }));

  return (
    <div className="space-y-6">
      {/* Incident Selector */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <Brain size={20} className="text-purple-400" />
          <h3 className="text-sm font-semibold text-cyber-text">AI Analysis for:</h3>
        </div>
        <div className="relative">
          <select
            value={selectedIncidentId}
            onChange={(e) => setSelectedIncidentId(e.target.value)}
            className="appearance-none rounded-lg border border-cyber-border bg-cyber-card px-4 py-2 pr-8 text-sm font-mono text-cyber-accent focus:border-cyber-accent focus:outline-none cursor-pointer"
          >
            {incidents?.map((inc) => (
              <option key={inc.incident_id} value={inc.incident_id}>
                {inc.title.slice(0, 40)}...
              </option>
            ))}
          </select>
          <ChevronDown size={14} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-cyber-muted pointer-events-none" />
        </div>
        <div className="flex items-center gap-2 ml-auto">
          <span className="text-xs text-cyber-muted">Confidence:</span>
          <span className={cn(
            'text-lg font-bold',
            analysisData.confidence >= 80 ? 'text-emerald-400' : analysisData.confidence >= 60 ? 'text-amber-400' : 'text-red-400'
          )}>
            {analysisData.confidence || 0}%
          </span>
        </div>
      </div>

      {/* AI Summary */}
      <Card
        title="AI Investigation Summary"
        subtitle="Automated analysis and threat assessment"
      >
        <div className="space-y-4">
          <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-4">
            <p className="text-sm text-cyber-text leading-relaxed">
              {analysisData.summary || 'No analysis available. Select an incident to view analysis.'}
            </p>
          </div>
        </div>
      </Card>

      {/* Two column layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Attack Narrative */}
        <Card title="Attack Narrative" subtitle="AI-reconstructed attack story">
          <p className="text-xs text-cyber-muted leading-relaxed whitespace-pre-line">
            {analysisData.attack_narrative || 'No narrative available.'}
          </p>
        </Card>

        {/* Threat Radar */}
        <Card title="Threat Profile" subtitle="Attack capability assessment">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#1e293b" />
                <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: '#64748b' }} />
                <PolarRadiusAxis tick={{ fontSize: 8, fill: '#64748b' }} domain={[0, 100]} />
                <Radar
                  name="Threat"
                  dataKey="score"
                  stroke="#8b5cf6"
                  fill="#8b5cf6"
                  fillOpacity={0.2}
                  strokeWidth={2}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Risk Assessment */}
      <Card title="Risk Assessment" subtitle="Current threat level evaluation">
        <div className="flex items-start gap-3">
          <div className="shrink-0 rounded-lg bg-red-500/15 p-2.5">
            <Target size={20} className="text-red-400" />
          </div>
          <div>
            <SeverityBadge severity="critical" size="md" />
            <p className="mt-2 text-sm text-cyber-text leading-relaxed">
              {analysisData.risk_assessment || 'No risk assessment available.'}
            </p>
          </div>
        </div>
      </Card>

      {/* Recommended Actions & MITRE */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recommended Actions */}
        <Card title="Recommended Actions" subtitle="AI-suggested response steps">
          <div className="space-y-2">
            {analysisData.recommended_actions && analysisData.recommended_actions.length > 0 ? (
              analysisData.recommended_actions.map((action: string, i: number) => (
                <div key={i} className="flex items-start gap-3 rounded-lg border border-cyber-border bg-cyber-bg/30 p-3">
                  <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-cyber-accent/15 text-[10px] font-bold text-cyber-accent">
                    {i + 1}
                  </div>
                  <p className="text-xs text-cyber-text leading-relaxed">{action}</p>
                </div>
              ))
            ) : (
              <p className="text-xs text-cyber-muted">No recommended actions available.</p>
            )}
          </div>
        </Card>

        {/* MITRE & Assets */}
        <div className="space-y-6">
          <Card title="MITRE ATT&CK Techniques" subtitle="Detected techniques">
            {analysisData.mitre_techniques && analysisData.mitre_techniques.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {analysisData.mitre_techniques.map((tech: string) => (
                  <span key={tech} className="rounded-md border border-purple-500/30 bg-purple-500/10 px-3 py-1.5 text-xs font-mono text-purple-400">
                    {tech}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-cyber-muted">No MITRE techniques detected.</p>
            )}
          </Card>

          <Card title="Affected Assets" subtitle="Systems and users impacted">
            {analysisData.affected_assets && analysisData.affected_assets.length > 0 ? (
              <div className="space-y-2">
                {analysisData.affected_assets.map((asset: string) => (
                  <div key={asset} className="flex items-center gap-2 rounded-lg border border-cyber-border bg-cyber-bg/30 px-3 py-2">
                    <Server size={14} className="text-cyber-accent shrink-0" />
                    <span className="text-xs font-mono text-cyber-text">{asset}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-cyber-muted">No affected assets identified.</p>
            )}
          </Card>
        </div>
      </div>

      {/* Timeline Reconstruction */}
      <Card title="AI Timeline Reconstruction" subtitle="Automated event correlation and sequencing">
        {analysisData.timeline_reconstruction && analysisData.timeline_reconstruction.length > 0 ? (
          <Timeline events={analysisData.timeline_reconstruction} />
        ) : (
          <p className="text-xs text-cyber-muted">No timeline data available.</p>
        )}
      </Card>
    </div>
  );
}
