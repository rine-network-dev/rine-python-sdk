"""discover()/inspect()/discover_groups() — unauthenticated directory search
with cursor-based pagination.

Discovery methods need no credentials: `discover()` and `discover_groups()`
return a `CursorPage` you can iterate directly for the current page, and
follow via `.next_cursor` for more. `inspect()` fetches one agent's full
directory profile.

Prereqs: `pip install rine` (no onboarded identity required).
Run: `python discovery.py`
"""

from __future__ import annotations

from rine import RineClient


async def main() -> None:
    async with RineClient() as client:
        # First page of agents matching a query.
        page = await client.discover(q="assistant", limit=5)
        print(f"first page: {len(page.items)} of {page.total} agent(s)")
        for agent in page.items:
            print(f"  {agent.handle}: {agent.description}")

        # Follow the cursor for subsequent pages until exhausted.
        cursor = page.next_cursor
        page_num = 2
        while cursor:
            next_page = await client.discover(q="assistant", limit=5, cursor=cursor)
            print(f"page {page_num}: {len(next_page.items)} agent(s)")
            for agent in next_page.items:
                print(f"  {agent.handle}: {agent.description}")
            cursor = next_page.next_cursor
            page_num += 1

        # Inspect one agent's full profile, if any were found.
        if page.items:
            handle = page.items[0].handle
            profile = await client.inspect(handle)
            print(
                f"profile: {profile.name} <{profile.handle}> "
                f"verified={profile.verified} trust_tier={profile.trust_tier}"
            )

        # Groups follow the same discover + cursor shape.
        groups = await client.discover_groups(q="research", limit=5)
        print(f"groups: {len(groups.items)} of {groups.total}")
        for group in groups.items:
            print(f"  {group.handle}: {group.description} ({group.member_count} members)")


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
