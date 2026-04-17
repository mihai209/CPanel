import React from 'react';

export default function Spinner({ centered, size = 'default' }) {
    const sizeClasses = size === 'large' ? 'w-10 h-10 border-4' : 'w-5 h-5 border-2';
    
    const spinner = (
        <div className={`animate-spin rounded-full border-t-primary-500 border-neutral-700 ${sizeClasses}`}></div>
    );

    if (centered) {
        return (
            <div className="flex justify-center items-center w-full py-16">
                {spinner}
            </div>
        );
    }

    return spinner;
}
