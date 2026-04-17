import React from 'react';

export default function PageContentBlock({ title, children, className = '' }) {
    React.useEffect(() => {
        if (title) {
            document.title = `${title} - CPanel`;
        }
    }, [title]);

    return (
        <div className={`w-full max-w-7xl mx-auto px-4 md:px-6 lg:px-8 py-6 ${className}`}>
            {title && (
                <div className="mb-6 flex justify-between items-center">
                    <h1 className="text-2xl font-bold text-neutral-100">{title}</h1>
                </div>
            )}
            <div className="w-full">
                {children}
            </div>
        </div>
    );
}
