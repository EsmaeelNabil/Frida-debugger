import React from 'react';

interface IconProps {
    image: ArrayBuffer;
    format: string;
    width: number;
    height: number;
}

interface IconBufferProps {
    icon: IconProps;
}

const IconBuffer: React.FC<IconBufferProps> = ({ icon }) => {
    const { image, format, width, height } = icon;
    const base64Image = arrayBufferToBase64(image);
    const src = `data:image/${format};base64,${base64Image}`;

    return (
        <img src={src} alt="icon" width={width} height={height} />
    );
};

// Utility function
function arrayBufferToBase64(buffer: ArrayBuffer): string {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

export default IconBuffer;
