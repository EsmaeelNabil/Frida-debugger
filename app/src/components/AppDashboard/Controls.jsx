import React from 'react';
import {Button} from 'evergreen-ui';

export function ControlButton(
    {
        text,
        iconBefore,
        action,
        visible
    }) {
    return (
        <div className='flex flex-row space-x-5 m-10 justify-center'>
            {visible ? (
                <Button iconBefore={iconBefore} onClick={action}>
                    {text}
                </Button>
            ) : (
                <></>
            )}
        </div>
    );
}
