defmodule BaseAclExWeb.Views.MetaView do
  use BaseAclExWeb, :view

  def render("meta.json", %{meta: meta}) do
    %{
      current_offset: meta.current_offset,
      current_page: meta.current_page,
      end_cursor: meta.end_cursor,
      has_next_page?: meta.has_next_page?,
      has_previous_page?: meta.has_previous_page?,
      next_offset: meta.next_offset,
      next_page: meta.next_page,
      page_size: meta.page_size,
      previous_offset: meta.previous_offset,
      previous_page: meta.previous_page,
      start_cursor: meta.start_cursor,
      total_count: meta.total_count,
      total_pages: meta.total_pages
    }
  end
end
