import React from 'react';

interface SeverityBadgeProps {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
}

const severityStyles: Record<SeverityBadgeProps['severity'], string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-blue-500 text-white',
  INFO: 'bg-gray-500 text-white',
};

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${severityStyles[severity]}`}
    >
      {severity}
    </span>
  );
};

export default SeverityBadge;
