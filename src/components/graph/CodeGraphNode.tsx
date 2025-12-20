
import React, { memo } from 'react';
import { Handle, Position } from 'reactflow';
import type { NodeProps } from 'reactflow';

/**
 * Custom node for the code graph that supports better text wrapping
 * and multiple connection handles on all sides.
 */
const CodeGraphNode = ({ data, selected }: NodeProps) => {
  const { label, type, style: customStyle } = data;

  // Define background colors based on node type
  const getBackgroundColor = (type: string) => {
    switch (type) {
      case 'file': return '#e0f2fe'; // Blue-ish
      case 'class': return '#dcfce7'; // Green-ish
      case 'method': return '#fef9c3'; // Yellow-ish
      default: return '#f3f4f6';
    }
  };

  const baseStyle: React.CSSProperties = {
    background: getBackgroundColor(type),
    color: '#1e293b',
    border: selected ? '2px solid #3b82f6' : '1px solid #94a3b8',
    padding: '8px 12px',
    borderRadius: '6px',
    fontSize: '12px',
    width: 'auto',
    minWidth: '120px',
    maxWidth: '300px',
    wordBreak: 'break-all',
    textAlign: 'center',
    boxShadow: selected ? '0 0 10px rgba(59, 130, 246, 0.5)' : '0 1px 3px rgba(0,0,0,0.1)',
    position: 'relative',
    transition: 'all 0.2s ease-in-out',
    ...customStyle // Allow overriding from external style (like search highlighting)
  };

  return (
    <div style={baseStyle}>
      {/* Multiple handles to allow edges to connect to the closest side */}
      <Handle type="target" position={Position.Top} id="top" style={{ background: '#64748b' }} />
      <Handle type="source" position={Position.Top} id="top-src" style={{ background: '#64748b', opacity: 0 }} />

      <Handle type="target" position={Position.Bottom} id="bottom" style={{ background: '#64748b' }} />
      <Handle type="source" position={Position.Bottom} id="bottom-src" style={{ background: '#64748b', opacity: 0 }} />

      <Handle type="target" position={Position.Left} id="left" style={{ background: '#64748b' }} />
      <Handle type="source" position={Position.Left} id="left-src" style={{ background: '#64748b', opacity: 0 }} />

      <Handle type="target" position={Position.Right} id="right" style={{ background: '#64748b' }} />
      <Handle type="source" position={Position.Right} id="right-src" style={{ background: '#64748b', opacity: 0 }} />

      <div className="font-medium text-xs">
        {label}
      </div>
    </div>
  );
};

export default memo(CodeGraphNode);
