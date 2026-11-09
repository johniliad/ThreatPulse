/*
 * Linkified free text.
 *
 * API prose (for example CISA notes) contains bare URLs. The text is split on
 * URL boundaries and each URL is rendered as a validated anchor — never as
 * HTML, so nothing in API data can be interpreted as markup.
 */

import { Fragment } from 'react';
import { splitExternalLinks } from '../../lib/urls';
import { ExternalLink } from './ExternalLink';

interface LinkifiedTextProps {
  text: string;
}

export function LinkifiedText({ text }: LinkifiedTextProps) {
  const segments = splitExternalLinks(text);

  return (
    <>
      {segments.map((segment, index) => {
        if (segment.type === 'link' && segment.href) {
          return (
            <ExternalLink key={`link-${index}`} href={segment.href}>
              {segment.text}
            </ExternalLink>
          );
        }

        return <Fragment key={`text-${index}`}>{segment.text}</Fragment>;
      })}
    </>
  );
}
