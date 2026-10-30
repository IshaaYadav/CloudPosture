import React from 'react';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  message?: string;
  text?: string;
}

const sizeMap: Record<NonNullable<LoadingSpinnerProps['size']>, { svg: string; stroke: number }> = {
  sm: { svg: 'w-6 h-6', stroke: 2 },
  md: { svg: 'w-10 h-10', stroke: 2 },
  lg: { svg: 'w-16 h-16', stroke: 2 },
};

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ size = 'md', message, text }) => {
  const { svg, stroke } = sizeMap[size];
  const displayText = message || text;

  return (
    <div className="flex flex-col items-center justify-center gap-3 py-8">
      <svg
        className={`animate-spin ${svg} text-blue-500`}
        xmlns="http://www.w3.org/2000/svg"
        fill="none"
        viewBox="0 0 24 24"
      >
        <circle
          className="opacity-25"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth={stroke}
        />
        <path
          className="opacity-75"
          fill="currentColor"
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
        />
      </svg>
      {displayText && (
        <p className="text-sm text-slate-500 dark:text-slate-400">{displayText}</p>
      )}
    </div>
  );
};

export default LoadingSpinner;
