import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import {
  TrashIcon,
  ShieldIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  InfoIcon,
  FolderIcon,
  LockIcon,
  RefreshIcon,
  SettingsIcon,
  ChevronIcon,
  CopyIcon,
  SearchIcon,
  XIcon,
  PlusIcon,
  EyeIcon,
  EditIcon,
  EmptyExclusionIcon,
} from './Icons';

const icons = [
  { name: 'TrashIcon', Component: TrashIcon },
  { name: 'ShieldIcon', Component: ShieldIcon },
  { name: 'AlertTriangleIcon', Component: AlertTriangleIcon },
  { name: 'CheckCircleIcon', Component: CheckCircleIcon },
  { name: 'InfoIcon', Component: InfoIcon },
  { name: 'FolderIcon', Component: FolderIcon },
  { name: 'LockIcon', Component: LockIcon },
  { name: 'RefreshIcon', Component: RefreshIcon },
  { name: 'SettingsIcon', Component: SettingsIcon },
  { name: 'CopyIcon', Component: CopyIcon },
  { name: 'SearchIcon', Component: SearchIcon },
  { name: 'XIcon', Component: XIcon },
  { name: 'PlusIcon', Component: PlusIcon },
  { name: 'EyeIcon', Component: EyeIcon },
  { name: 'EditIcon', Component: EditIcon },
  { name: 'EmptyExclusionIcon', Component: EmptyExclusionIcon },
];

describe('Icons', () => {
  icons.forEach(({ name, Component }) => {
    it(`${name} renders an SVG element`, () => {
      const { container } = render(<Component />);
      const svg = container.querySelector('svg');
      expect(svg).not.toBeNull();
    });
  });

  it('TrashIcon accepts custom size prop', () => {
    const { container } = render(<TrashIcon size={32} />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('width')).toBe('32');
    expect(svg?.getAttribute('height')).toBe('32');
  });

  it('ShieldIcon accepts custom className', () => {
    const { container } = render(<ShieldIcon className="custom" />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('class')).toBe('custom');
  });

  it('ChevronIcon renders and accepts open prop', () => {
    const { container: closed } = render(<ChevronIcon open={false} />);
    const svgClosed = closed.querySelector('svg');
    expect(svgClosed).not.toBeNull();
    expect(svgClosed?.style.transform).toContain('rotate(0deg)');

    const { container: open } = render(<ChevronIcon open={true} />);
    const svgOpen = open.querySelector('svg');
    expect(svgOpen?.style.transform).toContain('rotate(180deg)');
  });

  it('icons use default size when no size prop given', () => {
    const { container } = render(<TrashIcon />);
    const svg = container.querySelector('svg');
    expect(svg?.getAttribute('width')).toBe('16');
  });
});
